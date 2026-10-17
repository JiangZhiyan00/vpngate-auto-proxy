#!/usr/bin/env python3
"""生成自包含、固定版本和摘要的宿主准备附件。"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PROJECT = 'vpngate-auto-proxy'
VERSION = r'v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)'


def validate_manifest(value):
    fields = {'schema_version', 'project', 'release_tag', 'source_commit', 'installer_filename',
              'installer_sha256', 'policy_name', 'policy_sha256', 'policy_target', 'image_id', 'supported_hosts'}
    if not isinstance(value, dict) or set(value) != fields or type(value['schema_version']) is not int or value['schema_version'] != 1 or value['project'] != PROJECT:
        raise ValueError('宿主材料清单字段或版本无效')
    if any(not isinstance(value[key], str) for key in fields - {'schema_version', 'supported_hosts'}):
        raise ValueError('宿主材料清单字段类型无效')
    if not re.fullmatch(VERSION, value['release_tag']) or not re.fullmatch(r'[0-9a-f]{40}', value['source_commit']):
        raise ValueError('宿主材料版本或来源提交无效')
    if value['installer_filename'] != 'vap-host-init-' + value['release_tag'] + '.py':
        raise ValueError('安装器文件名不匹配')
    if any(not re.fullmatch(r'[0-9a-f]{64}', value[key]) for key in ('installer_sha256', 'policy_sha256')):
        raise ValueError('宿主材料摘要无效')
    if value['policy_name'] != PROJECT or value['policy_target'] != '/etc/apparmor.d/' + PROJECT:
        raise ValueError('宿主策略目标不匹配')
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', value['image_id']):
        raise ValueError('实际镜像身份无效')
    if value['supported_hosts'] != ['debian:12', 'ubuntu:24.04', 'linux/x86_64', 'systemd', 'docker:rootful-local', 'apparmor:enforce']:
        raise ValueError('支持矩阵不匹配')
    return value


def bootstrap_command(tag, filename, checksum):
    url = 'https://github.com/JiangZhiyan00/vpngate-auto-proxy/releases/download/' + tag + '/' + filename
    # 引导代码本身来自可信官方版本说明；HTTPS 重定向仅用于 GitHub 附件。
    code = '''import hashlib,os,pathlib,stat,sys,tempfile,time,urllib.request,urllib.parse,subprocess
if os.getuid()!=0 or os.geteuid()!=0: sys.exit("必须由管理员执行")
for directory in ("/","/run"):
 info=pathlib.Path(directory).lstat()
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_gid!=0 or stat.S_IMODE(info.st_mode)&0o022: sys.exit("下载临时目录必须由管理员保护")
class Redirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,req,fp,code,msg,headers,newurl):
  u=urllib.parse.urlsplit(newurl); h=u.hostname or ""
  if u.scheme!="https" or not (h=="github.com" or h.endswith(".githubusercontent.com")): raise ValueError("拒绝非官方附件重定向")
  return super().redirect_request(req,fp,code,msg,headers,newurl)
os.umask(0o077)
with tempfile.TemporaryDirectory(prefix="vap-host-init-",dir="/run") as d:
 p=pathlib.Path(d)/"installer.py"; total=0; start=time.monotonic(); sha=hashlib.sha256()
 with urllib.request.build_opener(Redirect).open(URL,timeout=15) as r,p.open("xb") as f:
  while True:
   b=r.read(65536)
   if not b: break
   total+=len(b)
   if total>1048576 or time.monotonic()-start>60: raise ValueError("附件下载超出限制")
   f.write(b); sha.update(b)
 if sha.hexdigest()!=SHA: sys.exit("安装器校验失败，未执行")
 sys.exit(subprocess.call([sys.executable,"-I",str(p)],env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LANG":"C.UTF-8"}))
'''
    code = 'URL=' + repr(url) + ';SHA=' + repr(checksum) + '\n' + code
    return 'sudo python3 -I -c ' + shlex.quote(code)


def package(tag, commit, image_id, output):
    if not isinstance(tag, str) or not re.fullmatch(VERSION, tag):
        raise ValueError('版本标签无效')
    if not isinstance(commit, str) or not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError('必须绑定完整来源提交')
    if not isinstance(image_id, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', image_id):
        raise ValueError('必须绑定实际镜像身份')
    policy = (ROOT / 'deploy/apparmor/vpngate-auto-proxy').read_bytes()
    source = (ROOT / 'scripts/host-init.py').read_text()
    license_text = (ROOT / 'LICENSE').read_text()
    embedded = {'release_tag': tag, 'source_commit': commit,
                'policy_base64': base64.b64encode(policy).decode(), 'policy_sha256': hashlib.sha256(policy).hexdigest()}
    marker = 'EMBEDDED_RELEASE = None'
    if source.count(marker) != 1:
        raise ValueError('安装器源码嵌入位置不唯一')
    source = source.replace(marker, 'EMBEDDED_RELEASE = ' + repr(embedded))
    source = source.replace('import argparse\n', '# 同版本项目许可：\n' + ''.join('# ' + line + '\n' for line in license_text.splitlines()) + 'import argparse\n', 1)
    filename = 'vap-host-init-' + tag + '.py'
    manifest = validate_manifest({'schema_version': 1, 'project': PROJECT, 'release_tag': tag, 'source_commit': commit,
        'installer_filename': filename, 'installer_sha256': hashlib.sha256(source.encode()).hexdigest(),
        'policy_name': PROJECT, 'policy_sha256': embedded['policy_sha256'], 'policy_target': '/etc/apparmor.d/' + PROJECT,
        'image_id': image_id, 'supported_hosts': ['debian:12', 'ubuntu:24.04', 'linux/x86_64', 'systemd', 'docker:rootful-local', 'apparmor:enforce']})
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    (output / filename).write_text(source)
    (output / 'host-setup.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    (output / 'host-setup-command.txt').write_text(bootstrap_command(tag, filename, manifest['installer_sha256']) + '\n\n'
        '从同版本官方发布取得本命令。固定版本及摘要校验通过后才执行；摘要不构成独立签名认证。\n'
        '只准备项目策略，不启动容器，不安装依赖，不重启其他服务。执行后仍须查询代理出口就绪。\n')
    return manifest


def main():
    parser = argparse.ArgumentParser(description='生成版本化宿主准备附件，不加载任何策略')
    parser.add_argument('--tag', required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--image-id', required=True)
    parser.add_argument('--output', type=Path, required=True)
    options = parser.parse_args()
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    if head != options.source_commit:
        raise ValueError('来源提交必须对应当前受测源码')
    subprocess.run(['git', 'ls-files', '--error-unmatch', 'scripts/host-init.py',
                    'scripts/package_host_init.py', 'deploy/apparmor/vpngate-auto-proxy'],
                   cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
    if subprocess.check_output(['git', 'diff', 'HEAD', '--', 'scripts/host-init.py',
                                'scripts/package_host_init.py', 'deploy/apparmor/vpngate-auto-proxy'], cwd=ROOT):
        raise ValueError('安装器及策略须先提交，不能将未提交材料绑定到旧来源提交')
    package(options.tag, head, options.image_id, options.output)


if __name__ == '__main__':
    main()
