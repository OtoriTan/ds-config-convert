"""与 dev-sidecar 自带用例 util.match.test.js 对齐的一致性测试。

原用例见 dev-sidecar `packages/mitmproxy/test/util.match.test.js`。
"""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.ds_match import build_index, domain_regexply, match_hostname  # noqa: E402

HOST_MAP = {
    "aaa.com": True,
    "*bbb.com": True,
    "*.ccc.com": True,
    "^.{1,3}ddd.com$": True,
    "*.cn": True,
    ".github.com": True,
    "*.eee.com": True,
    ".eee.com": False,  # 应被忽略，因为已有 *.eee.com
}


def test_domain_map_regexply():
    regexp_map, origin = build_index(HOST_MAP)

    for k in (
        r"^.*bbb\.com$",
        r"^.*\.ccc\.com$",
        "^.{1,3}ddd.com$",
        r"^.*\.cn$",
        r"^.*\.github\.com$",
        r"^.*\.eee\.com$",
    ):
        assert k in regexp_map, f"缺少编译后的键: {k}"

    for k in ("aaa.com", "*bbb.com", "*.ccc.com", "*.cn", "*.github.com"):
        assert origin.get(k) is True, f"origin 缺少快路径键: {k}"
    assert ".eee.com" not in origin, ".eee.com 应被 *.eee.com 覆盖而忽略"


def test_match_hostname():
    cases = [
        # (hostname, expected, 说明)
        ("aaa.com", True, "精确命中"),
        ("aaaa.com", None, "不应命中 aaa.com"),
        ("aaaa.comx", None, "不应命中 aaa.com"),
        ("bbb.com", True, "*bbb.com 的 * 可匹配 0 字符"),
        ("xbbb.com", True, "*bbb.com 前缀匹配"),
        ("bbb.comx", None, "后缀不符"),
        ("x.bbb.com", True, "*bbb.com 可跨越点号"),
        ("ccc.com", True, "*.ccc.com 的 * 可匹配 0 字符"),
        ("x.ccc.com", True, "*.ccc.com 子域"),
        ("xccc.com", None, "*.ccc.com 要求点号"),
        ("ddd.com", None, "^.{1,3}ddd.com$ 要求至少 1 字符"),
        ("x.ddd.com", True, "正则直通"),
        ("xddd.com", True, "正则直通"),
        ("zzz.cn", True, "*.cn 基域"),
        ("x.zzz.cn", True, "*.cn 子域"),
        ("zzz.cnet.com", None, ".cn 不是后缀"),
        ("github.com", True, ".github.com 归一为 *.github.com"),
        ("api.github.com", True, "子域"),
        ("aa.bb.github.com", True, "多级子域"),
        ("aaagithub.com", None, "要求点号边界"),
    ]

    for host, expected, note in cases:
        value, _ = match_hostname(HOST_MAP, host)
        assert value == expected, f"{host} 期望 {expected} 实际 {value}（{note}）"


def test_domain_regexply():
    assert domain_regexply("*foo.com") == r"^.*foo\.com$"
    assert domain_regexply("foo.com") == r"^foo\.com$"
    assert domain_regexply(".*") == "^.*$"


if __name__ == "__main__":
    test_domain_map_regexply()
    test_match_hostname()
    test_domain_regexply()
    print("全部通过")
