"""dev-sidecar 的 domainMapRegexply / matchHostname 的 Python 移植。

与 dev-sidecar `packages/mitmproxy/src/utils/util.match.js` 保持一致的语义：
  ① origin[hostname]          精确
  ② origin['*.' + hostname]
  ③ origin['*'  + hostname]
  ④ 正则按插入顺序，首个命中即返回
"""

import re

__all__ = ["domain_regexply", "build_index", "match_hostname"]


def domain_regexply(target: str) -> str:
    """等价于 JS 的 domainRegexply()：转义点号、* -> .*、套上 ^...$"""
    if target in (".*", "*", "true"):
        return "^.*$"
    return "^" + target.replace(".", "\\.").replace("*", ".*") + "$"


def build_index(host_map: dict):
    """等价于 JS 的 domainMapRegexply()，返回 (regexp_map, origin)。"""
    regexp_map: dict = {}
    origin: dict = {}

    for domain, value in host_map.items():
        if domain.startswith("."):
            # `.xxx.com` 归一为 `*.xxx.com`；若已有 `*.xxx.com` 则忽略
            if f"*{domain}" in host_map:
                continue
            domain = f"*{domain}"

        if "*" in domain or domain.startswith("^"):
            reg = domain if domain.startswith("^") else domain_regexply(domain)
            regexp_map[reg] = value
            # 只有「恰好一个 *，且位于第 0 位」才额外进 origin 快路径
            if domain.startswith("*") and domain.find("*") == domain.rfind("*") == 0:
                origin[domain] = value
        else:
            origin[domain] = value

    return regexp_map, origin


def match_hostname(host_map: dict, hostname: str):
    """返回 (value, 命中的键)；未命中返回 (None, None)。"""
    if not host_map:
        return None, None

    regexp_map, origin = build_index(host_map)

    for k in (hostname, f"*.{hostname}", f"*{hostname}"):
        if k in origin:
            return origin[k], k

    for reg, value in regexp_map.items():
        try:
            if re.search(reg, hostname):
                return value, reg
        except re.error:
            continue

    return None, None
