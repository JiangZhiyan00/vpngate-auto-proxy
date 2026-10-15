"""从已核验的离线归档关联配置摘要与镜像清单摘要。"""
import hashlib
import json
import tarfile


def archive_identities(archive, item):
    """只接受同一标签、配置内容和平台对应的摘要。"""
    def canonical(tag):
        parts = tag.split('/')
        if len(parts) == 1:
            return 'docker.io/library/' + tag
        if parts[0] == 'index.docker.io':
            parts[0] = 'docker.io'
        if not ('.' in parts[0] or ':' in parts[0] or parts[0] == 'localhost'):
            parts.insert(0, 'docker.io')
        return '/'.join(parts)

    with tarfile.open(archive, "r:*") as saved:
        def read(name):
            stream = saved.extractfile(name)
            if stream is None:
                raise ValueError("镜像归档缺少内容")
            return stream.read()

        def blob(descriptor):
            digest = descriptor["digest"]
            algorithm, value = digest.split(":", 1)
            if algorithm != "sha256" or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError("镜像归档摘要格式无效")
            data = read("blobs/sha256/" + value)
            if hashlib.sha256(data).hexdigest() != value or len(data) != descriptor["size"]:
                raise ValueError("镜像归档内容摘要不符")
            return json.loads(data)

        try:
            index = json.loads(read('index.json'))
        except KeyError:
            # 经典镜像存储的归档只有 manifest.json；没有可证明的清单摘要别名。
            records = [entry for entry in json.loads(read('manifest.json'))
                       if any(canonical(tag) == canonical(item['tag']) for tag in (entry.get('RepoTags') or []))]
            if len(records) != 1:
                raise ValueError('镜像归档标签无法唯一匹配')
            data = read(records[0]['Config'])
            identity = 'sha256:' + hashlib.sha256(data).hexdigest()
            config = json.loads(data)
            if identity != item['id']:
                raise ValueError('镜像归档与交付记录身份不符')
            if config['architecture'] != 'amd64' or config['os'] != 'linux':
                raise ValueError('镜像归档平台不符')
            return {identity}
        descriptors = [
            entry for entry in index["manifests"]
            if canonical(entry.get("annotations", {}).get("io.containerd.image.name", "")) == canonical(item["tag"])
        ]
        if len(descriptors) != 1:
            raise ValueError("镜像归档标签无法唯一匹配")
        descriptor = descriptors[0]
        manifest = blob(descriptor)
        config = blob(manifest["config"])
        identities = {descriptor["digest"], manifest["config"]["digest"]}
        if item["id"] not in identities:
            raise ValueError("镜像归档与交付记录身份不符")
        if config["architecture"] != "amd64" or config["os"] != "linux":
            raise ValueError("镜像归档平台不符")
        return identities


def verify_image(actual, item, identities):
    if actual["Id"] not in identities or actual["Architecture"] != "amd64" or actual["Os"] != "linux":
        raise ValueError("已加载镜像身份或架构不符，请重新执行 load")
