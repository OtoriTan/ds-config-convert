"""Cealing 三元组 -> dev-sidecar 规则。

Cealing 结构： [ [域名成员, ...], sni, ip ]

域名成员语法（官方 Wiki）：
  *            通配，匹配任意数量的任意字符
  a^b          包含 a，排除 b
  ^ 开头        禁用（注释）
  # 开头        仅浏览器伪造
  $ 开头        仅全局伪造

sni： null = 拔除 SNI 扩展；"" = 随机串；字符串 = 固定 SNI
ip ： ""   = 127.0.0.1；IP 字面量；域名（伪造时解析）
"""

import ipaddress

__all__ = ["parse_member", "convert"]


def _to_regex_fragment(p: str) -> str:
    """把 Cealing 的域名模式转成正则片段（不加锚点）。"""
    return p.replace(".", "\\.").replace("*", ".*")


def parse_member(member: str):
    """解析一个域名成员。

    Returns:
        (ds_key, excluded) —— ds_key 为 None 表示该成员被禁用/无效。
        excluded 非空时，ds_key 是一个带负向前瞻的正则（DS 没有 EXCLUDE）。
    """
    member = (member or "").strip()
    if not member or member.startswith("^"):
        return None, None  # ^ 开头 = 禁用/注释

    include, _, exclude = member.partition("^")
    include = include.strip().lstrip("#$")
    exclude = exclude.strip() or None

    if not include:
        return None, None

    if exclude:
        # Cealing 的 `MAP a sni, EXCLUDE b` 在 DS 里没有对应写法，
        # 用负向前瞻表达：^(?!<b>$)<a>$
        key = f"^(?!{_to_regex_fragment(exclude)}$){_to_regex_fragment(include)}$"
        return key, exclude

    return include, None


def _normalize_ip(raw: str):
    """返回 (ip_or_domain, kind)，kind ∈ {'ipv4','ipv6','domain','loopback'}"""
    raw = (raw or "").strip()
    if raw == "":
        return "127.0.0.1", "loopback"

    if raw.startswith("[") and raw.endswith("]"):
        raw = raw[1:-1]  # DS 的 preSetIpList 用裸 IPv6

    try:
        ip = ipaddress.ip_address(raw)
        return str(ip), ("ipv6" if ip.version == 6 else "ipv4")
    except ValueError:
        return raw, "domain"


def convert(raw_rules, allow_domain_targets: bool = True, empty_sni: str = "baidu.com"):
    """把 Cealing 规则数组转换成 dev-sidecar 的 intercepts / preSetIpList 片段。

    Args:
        allow_domain_targets: 是否保留「目标为域名」的规则（稍后解析成 IP）
        empty_sni: Cealing 中 sni=="" 时的替代 SNI。Cealing 的语义是「替换为不重复的
            随机串」——也就是**仍然要发 SNI，只是不暴露真实域名**。DS 没有随机 SNI，
            用 `""`（禁用 SNI）会改变行为：Cloudflare 这类前端在无 SNI 时直接回 alert，
            规则反而失效。所以这里用一个无关但合法的域名代替。

    Returns:
        dict: {"intercepts": {...}, "preSetIpList": {...}, "stats": {...}, "dropped": [...]}
    """
    intercepts: dict = {}
    pre_set: dict = {}
    stats = {
        "total": 0,
        "rules_used": 0,
        "members_used": 0,
        "disabled": 0,
        "excluded": 0,
        "ipv6": 0,
        "domain_target": 0,
        "invalid": 0,
    }
    dropped: list = []

    for item in raw_rules:
        stats["total"] += 1

        if not isinstance(item, list) or len(item) != 3:
            stats["invalid"] += 1
            dropped.append(("结构非法", item))
            continue

        domains, sni, target = item
        if not isinstance(domains, list) or not domains:
            stats["invalid"] += 1
            dropped.append(("域名数组为空", item))
            continue

        # --- sni ---
        # Cealing 的两态不能合并：
        #   null -> 拔除整个 SNI 扩展          -> DS 的 ""（空串是 DS 唯一特判值）
        #   ""   -> 替换为不重复的随机串        -> 仍需发 SNI，用一个无关域名代替
        # 两者都不能写成 "none"：DS 会把 "none" 当成真实的 SNI 字符串发出去。
        if sni is None:
            ds_sni = ""
        elif sni == "":
            ds_sni = empty_sni
        else:
            ds_sni = sni

        # --- ip ---
        ip, kind = _normalize_ip(target)
        if kind == "domain":
            stats["domain_target"] += 1
            if not allow_domain_targets:
                dropped.append(("目标为域名且未启用解析", item))
                continue
        if kind == "ipv6":
            stats["ipv6"] += 1

        used_any = False
        for member in domains:
            key, excluded = parse_member(member)
            if key is None:
                stats["disabled"] += 1
                continue
            if excluded:
                stats["excluded"] += 1

            intercepts.setdefault(key, {}).setdefault(".*", {})["sni"] = ds_sni
            if kind != "domain":
                pre_set.setdefault(key, {})[ip] = True
            else:
                # 目标为域名时先占位，稍后由 resolve_domain_targets() 展开
                pre_set.setdefault(key, {}).setdefault(f"__domain__:{ip}", True)

            used_any = True
            stats["members_used"] += 1

        if used_any:
            stats["rules_used"] += 1

    return {
        "intercepts": intercepts,
        "preSetIpList": pre_set,
        "stats": stats,
        "dropped": dropped,
    }
