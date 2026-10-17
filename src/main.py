"""ds-config-convert —— 把 Cealing 规则转换成 dev-sidecar 远程配置。

用法：
    python -m src.main --out dist/ds-config.json
    python -m src.main --out dist/ds-config.json --no-probe
    python -m src.main --sources official,cealing,cealing-c15412
"""

import argparse
import json
import socket
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import json5

from . import cealing as cealing_mod
from .merge import merge_configs
from .probe import probe_all
from .sources import SOURCES, fetch_json5, load_manual, set_use_proxy

CN_TZ = timezone(timedelta(hours=8))


def sort_json(obj):
    """按键长降序、同长字典序重排 —— 与 DS 的正则优先级模型对齐。"""
    if isinstance(obj, dict):
        items = sorted(obj.items(), key=lambda kv: (-len(str(kv[0])), str(kv[0])))
        return {k: sort_json(v) for k, v in items}
    if isinstance(obj, list):
        return [sort_json(x) for x in obj]
    return obj


def resolve_domain_targets(pre_set: dict, timeout=5.0):
    """把 `__domain__:xxx` 占位符展开成真实 IP。

    注意：解析结果取决于构建机所在位置。Akamai 这类 GSLB 会按解析者位置返回不同边缘，
    因此这一步在中国境外跑出来的 IP 未必对国内用户有效。
    """
    resolved, failed = 0, []
    for key, ip_map in list(pre_set.items()):
        placeholders = [ip for ip in ip_map if ip.startswith("__domain__:")]
        if not placeholders:
            continue
        for ph in placeholders:
            host = ph.split(":", 1)[1]
            ip_map.pop(ph, None)
            try:
                infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
                ips = sorted({i[4][0] for i in infos})
                for ip in ips:
                    ip_map[ip] = True
                resolved += 1
            except Exception:  # noqa: BLE001
                failed.append(host)
        if not ip_map:
            pre_set.pop(key, None)
    return resolved, failed


def apply_manual(merged: dict, manual: dict) -> int:
    """把手写规则并入最终配置，返回并入的条目数。

    intercepts / preSetIpList 按键覆盖；dns.ech 的 domains / preSetIpDomains 是数组，
    整体替换会把官方条目全部冲掉，所以按并集追加。
    """
    server = merged.setdefault("server", {})
    mserver = manual.get("server") or {}
    n = 0

    for sec in ("intercepts", "preSetIpList"):
        for key, val in (mserver.get(sec) or {}).items():
            if isinstance(val, dict):
                server.setdefault(sec, {}).setdefault(key, {}).update(val)
                n += 1

    mech = (mserver.get("dns") or {}).get("ech") or {}
    for field in ("domains", "preSetIpDomains"):
        extra = mech.get(field)
        if not isinstance(extra, list) or not extra:
            continue
        target = server.setdefault("dns", {}).setdefault("ech", {}).setdefault(field, [])
        added = [x for x in extra if x not in target]
        target.extend(added)
        n += len(added)

    return n


def main(argv=None):
    ap = argparse.ArgumentParser(description="Cealing -> dev-sidecar 配置转换器")
    ap.add_argument("--out", default="dist/ds-config.json")
    ap.add_argument("--sources", default="official,cealing")
    ap.add_argument("--manual", default="config/manual.json5")
    ap.add_argument("--meta-id", default="io.github.ds-config-convert")
    ap.add_argument("--no-probe", action="store_true", help="关闭 TLS 探测（纯离线转换）")
    ap.add_argument("--no-strict", action="store_true", help="允许第三方覆盖官方已覆盖的域名")
    ap.add_argument("--no-resolve", action="store_true", help="不解析「目标为域名」的规则")
    ap.add_argument("--timeout", type=float, default=6.0)
    ap.add_argument("--no-proxy", action="store_true", help="忽略环境变量里的 HTTP(S)_PROXY")
    ap.add_argument(
        "--empty-sni",
        default="baidu.com",
        help="Cealing 中 sni 为空串（随机 SNI）时使用的替代域名，默认 baidu.com",
    )
    args = ap.parse_args(argv)

    if args.no_proxy:
        set_use_proxy(False)

    names = [s.strip() for s in args.sources.split(",") if s.strip()]
    for n in names:
        if n not in SOURCES:
            ap.error(f"未知来源: {n}（可选: {', '.join(SOURCES)}）")

    # 1. 官方配置作为基底
    print(f"[1/6] 拉取官方配置: {SOURCES['official'][0]}")
    official = fetch_json5(SOURCES["official"])

    # 2. 转换各 Cealing 来源
    combined = {"intercepts": {}, "preSetIpList": {}}
    stats_all = {}
    for n in names:
        if n == "official":
            continue
        print(f"[2/6] 拉取并转换: {n}")
        raw = fetch_json5(SOURCES[n])
        conv = cealing_mod.convert(
            raw,
            allow_domain_targets=not args.no_resolve,
            empty_sni=args.empty_sni,
        )
        stats_all[n] = conv["stats"]
        for sec in ("intercepts", "preSetIpList"):
            for k, v in conv[sec].items():
                combined[sec].setdefault(k, {}).update(v)

    # 3. 展开「目标为域名」的规则
    if not args.no_resolve:
        print("[3/6] 解析目标为域名的规则")
        ok, bad = resolve_domain_targets(combined["preSetIpList"])
        print(f"      展开 {ok} 个，失败 {len(bad)} 个" + (f"（{bad[:5]}）" if bad else ""))
    else:
        print("[3/6] 跳过域名解析（--no-resolve）")
        for key in list(combined["preSetIpList"]):
            ip_map = combined["preSetIpList"][key]
            for ip in [i for i in ip_map if i.startswith("__domain__:")]:
                ip_map.pop(ip, None)
            if not ip_map:
                combined["preSetIpList"].pop(key, None)

    # 4. 语义归并
    print("[4/6] 语义归并（官方已覆盖的域名不接管）")
    merged, report = merge_configs(official, combined, strict=not args.no_strict)
    print(f"      新增 {len(report['pre_added'])} 条 preSetIpList，"
          f"跳过 {len(report['pre_skipped'])} 条（官方已覆盖）")

    # 4.5 手写规则最后覆盖，优先级最高
    manual = load_manual(args.manual)
    if manual:
        n_manual = apply_manual(merged, manual)
        print(f"      手写规则覆盖 {n_manual} 条")

    # 5. TLS 探测 —— 只删「服务端主动拒绝」的 IP
    removed = []
    if not args.no_probe:
        print("[5/6] TLS 探测（只删 TLS alert，超时保留）")
        itc = merged["server"].get("intercepts", {})
        pre = merged["server"].get("preSetIpList", {})
        targets = []
        for key in report["pre_added"]:
            sni = ""
            for opt in (itc.get(key) or {}).values():
                if isinstance(opt, dict) and "sni" in opt:
                    sni = opt["sni"]
                    break
            for ip in (pre.get(key) or {}):
                targets.append((key, ip, sni))
        print(f"      待探测 {len(targets)} 个 IP")
        results = probe_all(targets, timeout=args.timeout) if targets else {}
        for (key, ip), res in results.items():
            if res == "alert":
                pre.get(key, {}).pop(ip, None)
                removed.append((key, ip))
        for key in list(pre):
            if not pre[key]:
                pre.pop(key)
        print(f"      删除 {len(removed)} 个服务端拒绝的 IP")
    else:
        print("[5/6] 跳过探测（--no-probe）")

    # 6. 输出
    print("[6/6] 写出配置")
    now = datetime.now(CN_TZ).strftime("%Y%m%d%H%M")
    merged.setdefault("metaInfo", {})
    merged["metaInfo"].update(
        {
            "id": args.meta_id,
            "version": now,
            "updateLog": (
                f"基于 {','.join(names)} 自动生成；"
                f"新增 {len(report['pre_added'])} 条规则，"
                f"跳过 {len(report['pre_skipped'])} 条官方已覆盖域名，"
                f"删除 {len(removed)} 个服务端拒绝的 IP"
            ),
        }
    )

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json5.dump(sort_json(merged), f, ensure_ascii=False, indent=2)

    print()
    print(f"输出: {out}  ({out.stat().st_size:,} 字节)")
    print(f"  intercepts   : {len(merged['server'].get('intercepts', {}))}")
    print(f"  preSetIpList : {len(merged['server'].get('preSetIpList', {}))}")
    print(f"  version      : {now}")
    for n, s in stats_all.items():
        print(f"  [{n}] 规则 {s['rules_used']}/{s['total']}，"
              f"域名成员 {s['members_used']}，禁用 {s['disabled']}，"
              f"含排除 {s['excluded']}，IPv6 {s['ipv6']}，域名目标 {s['domain_target']}")

    if report["pre_skipped"]:
        print("\n被跳过的域名（官方已覆盖，样例 10 条）:")
        for key, hit in report["pre_skipped"][:10]:
            print(f"  {key}  ->  官方键 {hit}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
