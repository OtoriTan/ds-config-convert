"""语义归并。

核心规则（与文本无关，只看语义）：
  官方已覆盖的域名，第三方规则不接管 —— 因为 DS 的 matchHostname 是「首个命中即返回、
  不合并值」，一条单 IP 的字面量键会无条件压过官方的多 IP 正则键，落败方的 IP 集合
  会被整体丢弃。cute 的 Steam 故障就是这么来的。

  未被官方覆盖的域名，才把第三方的键放进去。
"""

import copy

from .ds_match import match_hostname

__all__ = ["sample_host", "covered_by", "merge_configs"]


def sample_host(key: str):
    """从一个主机模式里取一个具体主机名，用来判断是否被别的键覆盖。

    正则键（^ 开头）取不出样本，返回 None —— 这类键一律按「未被覆盖」处理。
    """
    if not key or key.startswith("^"):
        return None
    if key.startswith("*."):
        return "x" + key[1:]
    if key.startswith("*"):
        return key[1:]
    return key


def covered_by(host_map: dict, key: str):
    """官方是否已覆盖 key 所代表的域名。返回命中的官方键名或 None。"""
    host = sample_host(key)
    if not host:
        return None
    _, hit = match_hostname(host_map, host)
    return hit


def merge_configs(official: dict, extra: dict, strict: bool = True):
    """以官方配置为基底，把 extra 并进去。

    Args:
        official: 官方 DS 配置（会被深拷贝，不修改入参）
        extra: Cealing 转换产物，形如 {"intercepts": {...}, "preSetIpList": {...}}
        strict: True 时官方已覆盖的域名不接管

    Returns:
        (merged_config, report)
    """
    out = copy.deepcopy(official)
    server = out.setdefault("server", {})
    itc = server.setdefault("intercepts", {})
    pre = server.setdefault("preSetIpList", {})

    off_itc = official.get("server", {}).get("intercepts", {}) or {}
    off_pre = official.get("server", {}).get("preSetIpList", {}) or {}

    report = {"pre_added": [], "pre_skipped": [], "itc_added": [], "itc_skipped": []}

    for key, ip_map in (extra.get("preSetIpList") or {}).items():
        if strict:
            hit = covered_by(off_pre, key)
            if hit:
                report["pre_skipped"].append((key, hit))
                continue
        dst = pre.setdefault(key, {})
        for ip, val in ip_map.items():
            dst.setdefault(ip, val)
        report["pre_added"].append(key)

    for key, opts in (extra.get("intercepts") or {}).items():
        if strict and covered_by(off_itc, key):
            report["itc_skipped"].append(key)
            continue
        dst = itc.setdefault(key, {})
        for url_pat, opt in opts.items():
            dst.setdefault(url_pat, opt)
        report["itc_added"].append(key)

    return out, report
