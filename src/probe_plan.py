"""Choose conservative TLS probe parameters from the merged DS configuration."""

import re
from dataclasses import dataclass

from .ds_match import build_index


@dataclass(frozen=True)
class ProbePlan:
    hostname: str | None
    sni: str | None
    can_remove: bool
    reason: str


def _matching_values(host_map, hostname):
    """Return all matching values, or None if a pattern cannot be evaluated.

    DS merges matching intercept rules; selecting its first hostname match is not
    sufficient.  Named groups use JavaScript syntax in DS and Python syntax here.
    If a pattern is not understood, retain the IP instead of guessing.
    """
    if not isinstance(host_map, dict):
        return None
    regexp_map, origin = build_index(host_map)
    values = []
    for pattern, value in regexp_map.items():
        pattern = re.sub(r"\(\?<([A-Za-z][A-Za-z0-9_]*)>", r"(?P<\1>", pattern)
        try:
            if re.search(pattern, hostname):
                values.append(value)
        except re.error:
            return None
    for key in (f"*{hostname}", f"*.{hostname}", hostname):
        if key in origin:
            values.append(origin[key])
    return values


def _representative(key):
    """Return a concrete hostname, and whether it is an exact rule.

    A bare suffix is a useful diagnostic for a leading-star rule, but is not
    proof that every matching subdomain has identical routing.
    """
    if not isinstance(key, str) or not key or key.startswith("^"):
        return None, False
    exact = "*" not in key
    if not exact:
        if key.count("*") != 1 or not key.startswith("*"):
            return None, False
        key = key[1:].lstrip(".")
    if len(key) > 253 or not re.fullmatch(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", key):
        return None, False
    if any(len(part) > 63 or part.startswith("-") or part.endswith("-") for part in key.split(".")):
        return None, False
    return key, exact


def plan_probe(key, intercepts, dns):
    """Plan a probe; ambiguous or ECH-specific cases never authorize deletion."""
    hostname, exact = _representative(key)
    if hostname is None:
        return ProbePlan(None, None, False, "no concrete hostname")

    ech = (dns or {}).get("ech") or {}
    if ech.get("enabled", True) is not False and ech.get("use", True) is not False:
        domains = ech.get("domains") or []
        if isinstance(domains, list):
            ech_map = {d: True for d in domains if isinstance(d, str) and d}
        elif isinstance(domains, dict):
            ech_map = {d: v for d, v in domains.items() if v is not False and v is not None}
        else:
            return ProbePlan(hostname, None, False, "invalid ECH domains")
        matches = _matching_values(ech_map, hostname)
        if matches is None or matches:
            return ProbePlan(hostname, None, False, "ECH or unknown ECH matching")

    matches = _matching_values(intercepts or {}, hostname)
    if matches is None:
        return ProbePlan(hostname, None, False, "unsupported hostname pattern")
    snis = set()
    missing_sni = False
    for paths in matches:
        if not isinstance(paths, dict):
            return ProbePlan(hostname, None, False, "unsupported intercept rule")
        for option in paths.values():
            if option is None:
                continue
            if not isinstance(option, dict) or option.get("proxy"):
                return ProbePlan(hostname, None, False, "proxy or unsupported path")
            sni = option.get("sni")
            if sni is None:
                missing_sni = True
            elif isinstance(sni, str):
                snis.add(sni)
            else:
                return ProbePlan(hostname, None, False, "invalid SNI")
    if len(snis) > 1 or (snis and missing_sni):
        return ProbePlan(hostname, None, False, "ambiguous SNI across matched paths")
    # DS normally uses the real hostname if no SNI override exists. An explicit
    # empty string is different: DS sends no SNI extension.
    sni = next(iter(snis)) if snis else hostname
    return ProbePlan(hostname, sni, exact, "exact hostname" if exact else "wildcard diagnostic only")


def build_probe_targets(keys, intercepts, pre, dns):
    """Build existing probe_all inputs and remember which results can delete."""
    targets, removable, skipped = [], set(), []
    for key in keys:
        plan = plan_probe(key, intercepts, dns)
        if plan.sni is None:
            skipped.append((key, plan.reason))
            continue
        for ip in pre.get(key, {}):
            targets.append((key, ip, plan.sni))
            if plan.can_remove:
                removable.add((key, ip))
    return targets, removable, skipped

def remove_rejected(results, pre, removable):
    """Delete only confidently scoped IPs after an active TLS alert."""
    removed = []
    for (key, ip), result in results.items():
        ip_map = pre.get(key, {})
        if result == "alert" and (key, ip) in removable and ip in ip_map:
            ip_map.pop(ip)
            removed.append((key, ip))
    return removed