"""上游配置抓取。"""

import json5
import requests

__all__ = ["SOURCES", "fetch_json5", "load_manual", "set_use_proxy"]

UA = "ds-config-convert/1.0"

# 是否信任环境变量里的 HTTP(S)_PROXY。某些本地环境（如沙箱）的代理会拦 raw.githubusercontent，
# 这时用 --no-proxy 关掉。
_USE_PROXY = True


def set_use_proxy(flag: bool):
    global _USE_PROXY
    _USE_PROXY = flag


SOURCES = {
    # 官方共享配置（dev-sidecar 客户端默认拉的就是这个）
    "official": "https://ds-official-config.bestar.de5.net/remote_config.json5",
    # Cealing-Host 主仓库
    "cealing": "https://raw.githubusercontent.com/SpaceTimee/Cealing-Host/main/Cealing-Host.json",
    # Cealing 的多 IP 优选分支
    "cealing-c15412": "https://raw.githubusercontent.com/c15412/Cealing-Host/main/Cealing-Host.json",
}


def _candidates(url: str):
    """直连 + jsDelivr 镜像。"""
    yield url
    if "raw.githubusercontent.com/" in url:
        tail = url.split("raw.githubusercontent.com/", 1)[1]  # owner/repo/branch/path
        parts = tail.split("/", 3)
        if len(parts) == 4:
            owner, repo, branch, path = parts
            yield f"https://cdn.jsdelivr.net/gh/{owner}/{repo}@{branch}/{path}"


def fetch_text(url: str, timeout=(10, 30)) -> str:
    errors = []
    for u in _candidates(url):
        try:
            with requests.Session() as s:
                s.trust_env = _USE_PROXY
                r = s.get(u, timeout=timeout, headers={"User-Agent": UA})
                r.raise_for_status()
                return r.text
        except Exception as e:  # noqa: BLE001
            errors.append(f"{u} -> {type(e).__name__}: {str(e)[:80]}")
    raise RuntimeError("全部镜像均失败:\n  " + "\n  ".join(errors))


def fetch_json5(url: str):
    return json5.loads(fetch_text(url))


def load_manual(path):
    """本地手写规则，与 DS 配置同格式（可为空）。"""
    try:
        with open(path, encoding="utf-8") as f:
            return json5.load(f)
    except FileNotFoundError:
        return {}
