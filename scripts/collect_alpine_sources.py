"""按实际镜像包的 aports 提交收集构建配方、补丁和源码，逐项复核 SHA512。"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import re
import time
import tarfile
import urllib.error
import urllib.request
import urllib.parse


def checksums(recipe):
    match = re.search(r'^sha512sums=([\"\x27])(.*?)\1', recipe, re.MULTILINE | re.DOTALL)
    if not match:
        raise ValueError("构建配方没有可核验的 SHA512 清单")
    result = {}
    for line in match[2].strip().splitlines():
        fields = line.strip().split()
        if len(fields) != 2 or not re.fullmatch(r'[0-9a-f]{128}', fields[0]):
            raise ValueError("构建配方摘要格式无效")
        name = fields[1]
        if not re.fullmatch(r'[A-Za-z0-9_.+@=-]+', name) or name in ('.', '..') or name in result:
            raise ValueError("构建配方文件名越界或重复")
        result[name] = fields[0]
    if not result:
        raise ValueError("构建配方摘要清单为空")
    return result


def download(url, path, expected=None):
    if path.is_symlink():
        raise ValueError("拒绝来源缓存中的符号链接")
    if expected and path.is_file() and hashlib.sha512(path.read_bytes()).hexdigest() == expected:
        return
    temporary = path.with_name(path.name + '.part')
    for attempt in range(3):
        try:
            request = urllib.request.Request(url, headers={'User-Agent': 'vpngate-source-materials/1'})
            with urllib.request.urlopen(request, timeout=45) as response, temporary.open('wb') as stream:
                digest = hashlib.sha512()
                while block := response.read(1024 * 1024):
                    digest.update(block)
                    stream.write(block)
            if expected and digest.hexdigest() != expected:
                raise ValueError("来源文件摘要不符：" + path.name)
            temporary.replace(path)
            return
        except urllib.error.HTTPError as error:
            temporary.unlink(missing_ok=True)
            if error.code in (404, 403) or attempt == 2:
                raise
        except (OSError, TimeoutError):
            temporary.unlink(missing_ok=True)
            if attempt == 2:
                raise
        time.sleep(1 + attempt)


def collect_origin(origin, commit, destination, branch):
    if not re.fullmatch('[a-zA-Z0-9_.+-]+', origin) or not re.fullmatch('[0-9a-f]{40}', commit):
        raise ValueError("实际镜像来源标识无效")
    directory = destination / (origin + '-' + commit)
    directory.mkdir(parents=True, exist_ok=True)
    base = None
    location = directory / 'recipe-location.json'
    if location.is_file():
        candidate = json.loads(location.read_text()).get('url', '')
        if candidate in [f'https://raw.githubusercontent.com/alpinelinux/aports/{commit}/{section}/{origin}/'
                         for section in ('main', 'community', 'testing')] and (directory / 'APKBUILD').is_file():
            base = candidate
    for section in ('main', 'community', 'testing'):
        if base is not None:
            break
        candidate = f'https://raw.githubusercontent.com/alpinelinux/aports/{commit}/{section}/{origin}/'
        try:
            download(candidate + 'APKBUILD', directory / 'APKBUILD')
            base = candidate
            break
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise
    if base is None:
        raise ValueError("找不到固定提交的构建配方：" + origin)
    location.write_text(json.dumps({'url': base}) + '\n')
    recipe = (directory / 'APKBUILD').read_text()
    recipe_files = collect_recipe_files(base, commit, directory)
    upstream = upstream_urls(recipe)
    records, missing = [], []
    if not re.search(r'^source\+?=', recipe, re.MULTILINE) and not re.search(r'^sha512sums=', recipe, re.MULTILINE):
        # alpine-base 等元包完全由构建配方生成，没有外部源码声明。
        declared = {}
    else:
        declared = checksums(recipe)
    for name, expected in declared.items():
        path = directory / name
        urls = [base + name, f'https://distfiles.alpinelinux.org/distfiles/{branch}/{name}']
        if name.endswith(('.gz', '.xz', '.bz2', '.zip', '.tgz', '.zst')):
            urls.reverse()
        urls.extend(upstream.get(name, []))
        failure = None
        for url in urls:
            try:
                download(url, path, expected)
                records.append({'name': name, 'sha512': expected, 'url': url,
                                'size': path.stat().st_size})
                failure = None
                break
            except (OSError, ValueError) as error:
                failure = str(error)
        if failure is not None:
            missing.append({'name': name, 'error': failure})
    print(f"系统源码：{origin}，已核验 {len(records)} 项，缺失 {len(missing)} 项", flush=True)
    return {'origin': origin, 'source_commit': commit, 'recipe_url': base + 'APKBUILD',
            'recipe_sha256': hashlib.sha256((directory / 'APKBUILD').read_bytes()).hexdigest(),
            'directory': directory.name, 'recipe_files': recipe_files,
            'sources': records, 'missing': missing}


def upstream_urls(recipe):
    """只替换配方中的简单版本变量，不运行 shell、命令替换或构建函数。"""
    values = {}
    for match in re.finditer(r'^([A-Za-z_][A-Za-z_0-9]*)=(?:"([^"\n]*)"|\x27([^\x27\n]*)\x27|([^\s#]+))', recipe, re.MULTILINE):
        values[match[1]] = next(value for value in match.groups()[1:] if value is not None)

    def substitute(value):
        for _ in range(10):
            previous = value
            value = re.sub(r'\$\{([A-Za-z_][A-Za-z_0-9]*)%\.\*\}',
                           lambda m: values.get(m[1], m[0]).rsplit('.', 1)[0], value)
            value = re.sub(r'\$\{([A-Za-z_][A-Za-z_0-9]*)\}|\$([A-Za-z_][A-Za-z_0-9]*)',
                           lambda m: values.get(m[1] or m[2], m[0]), value)
            if value == previous:
                break
        return value

    match = re.search(r'^source=([\"\x27])(.*?)\1', recipe, re.MULTILINE | re.DOTALL)
    result = {}
    if match:
        for token in match[2].split():
            token = substitute(token)
            alias, separator, url = token.partition('::')
            if not separator:
                url = token
            if url.startswith('http://'):
                url = 'https://' + url[7:]
            if not url.startswith('https://') or '$' in url or '`' in url:
                continue
            filename = alias if separator else Path(urllib.parse.urlsplit(url).path).name
            result.setdefault(filename, []).append(url)
    return result


def collect_recipe_files(base, commit, directory):
    """同时保留安装脚本、触发器等不在 source 摘要列表里的完整配方目录。"""
    repository_path = base.split('/' + commit + '/', 1)[1].rstrip('/')
    records = []
    index = directory / 'recipe-index.json'
    if index.exists():
        cached = json.loads(index.read_text())
        if cached and all((directory / 'recipe' / item['path']).is_file()
                          and hashlib.sha256((directory / 'recipe' / item['path']).read_bytes()).hexdigest() == item['sha256']
                          for item in cached):
            return cached

    def visit(relative=''):
        path = repository_path + ('/' + relative if relative else '')
        cache = directory / ('tree-' + hashlib.sha256(path.encode()).hexdigest()[:16] + '.json')
        if not cache.exists():
            download('https://api.github.com/repos/alpinelinux/aports/contents/' + path + '?ref=' + commit, cache)
        entries = json.loads(cache.read_text())
        if not isinstance(entries, list):
            raise ValueError('固定配方目录列表格式错误')
        for entry in entries:
            name = entry['name']
            if '/' in name or name in ('.', '..'):
                raise ValueError('固定配方目录文件名越界')
            local = relative + '/' + name if relative else name
            if len(records) > 1000 or len(Path(local).parts) > 10:
                raise ValueError('固定配方目录超限')
            if entry['type'] == 'dir':
                visit(local)
            elif entry['type'] == 'file':
                output = directory / 'recipe' / local
                output.parent.mkdir(parents=True, exist_ok=True)
                if not output.exists():
                    cached = directory / local
                    data = cached.read_bytes() if cached.is_file() else b''
                    blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
                    if cached.is_file() and blob == entry['sha']:
                        output.write_bytes(data)
                    else:
                        download(base + urllib.parse.quote(local), output)
                data = output.read_bytes()
                # GitHub tree 的 blob 标识绑定 git 对象头及正文，防止缓存误配。
                blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
                if blob != entry['sha']:
                    raise ValueError('固定配方文件 git 对象摘要不符：' + local)
                records.append({'path': local, 'sha256': hashlib.sha256(data).hexdigest(),
                                'git_blob': entry['sha']})
            else:
                raise ValueError('固定配方目录包含尚未处理的链接：' + local)
    try:
        visit()
    except (urllib.error.HTTPError, urllib.error.URLError):
        # 公共目录 API 可能限流；固定提交的完整快照仍提供同一配方目录。
        records = []
        cache = directory.parent / '_aports-cache'
        cache.mkdir(exist_ok=True)
        snapshot = cache / (commit + '.tar.gz')
        url = 'https://codeload.github.com/alpinelinux/aports/tar.gz/' + commit
        if not snapshot.exists():
            download(url, snapshot)
        digest = hashlib.sha256(snapshot.read_bytes()).hexdigest()
        prefix = 'aports-' + commit + '/' + repository_path + '/'
        with tarfile.open(snapshot) as archive:
            for member in archive:
                if not member.name.startswith(prefix) or member.isdir():
                    continue
                relative = Path(member.name[len(prefix):])
                if not member.isfile() or relative.is_absolute() or '..' in relative.parts:
                    raise ValueError('配方快照含链接或越界成员')
                data = archive.extractfile(member).read()
                output = directory / 'recipe' / relative
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_bytes(data)
                records.append({'path': relative.as_posix(), 'sha256': hashlib.sha256(data).hexdigest(),
                                'snapshot_url': url, 'snapshot_sha256': digest})
        if not records:
            raise ValueError('固定提交快照中未找到完整配方目录')
    if (directory / 'recipe/APKBUILD').read_bytes() != (directory / 'APKBUILD').read_bytes():
        raise ValueError('完整配方目录与来源配方不一致')
    index.write_text(json.dumps(records, ensure_ascii=False, indent=2) + '\n')
    return records


def main():
    parser = argparse.ArgumentParser(description="收集实际镜像系统包对应源码；缺失时失败")
    parser.add_argument('--inventory', type=Path, default=Path('docs/third-party/inventory.json'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--branch', default='v3.22', choices=['v3.22'])
    options = parser.parse_args()
    inventory = json.loads(options.inventory.read_text())
    options.output.mkdir(parents=True, exist_ok=True)
    origins = sorted({(package['origin'], package['source_commit'])
                      for package in inventory['runtime_image']['packages']})
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(collect_origin, origin, commit, options.output, options.branch)
                   for origin, commit in origins]
        records, failures = [], []
        for (origin, _), future in zip(origins, futures):
            try:
                records.append(future.result())
            except Exception as error:
                failures.append({'origin': origin, 'error': str(error)})
    complete = not failures and all(not record['missing'] for record in records)
    report = {'schema_version': 1, 'image_id': inventory['runtime_image']['id'],
              'inventory_sha256': hashlib.sha256(options.inventory.read_bytes()).hexdigest(),
              'status': 'passed' if complete else 'failed',
              'package_count': len(inventory['runtime_image']['packages']),
              'origins': records, 'failures': failures}
    (options.output / 'manifest.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    if not complete:
        raise SystemExit('部分系统源码尚未取得，详见来源清单；不能标记分发材料完成')
    print(f'全部 {len(origins)} 个来源及其构建配方、补丁和源码已归档')


if __name__ == '__main__':
    main()
