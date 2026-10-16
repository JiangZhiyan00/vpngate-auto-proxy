"""从已选定镜像读取真实产品快照，供分发摘要核对。"""
import subprocess


def program_bytes(image, platform='linux/amd64'):
    return subprocess.check_output([
        'docker', 'run', '--rm', '--platform', platform, '--network', 'none',
        '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--read-only',
        '--entrypoint', 'cat', image, '/usr/local/bin/vap',
    ])
