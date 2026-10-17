"""TLS 握手探测 —— 只做「减法」。

判据（刻意保守）：
  收到 TLS alert  -> 'alert'   服务端主动拒绝，与路径无关，可以删
  握手成功        -> 'ok'
  其它（超时/重置）-> 'unknown' 路径相关，一律保留

之所以只删 alert：构建机的网络不是使用环境，超时在构建机上完全可能是通的，
删掉会误伤本地可用的 IP。可达性交给 DS 运行期的 TCP 测速去淘汰。
"""

import concurrent.futures
import socket
import ssl

__all__ = ["probe", "probe_all"]


def probe(ip: str, sni: str | None, timeout: float = 6.0) -> str:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    server_hostname = sni if sni else None  # 空 SNI -> 不发 SNI 扩展

    try:
        with socket.create_connection((ip, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=server_hostname):
                return "ok"
    except ssl.SSLError as e:
        reason = (getattr(e, "reason", "") or str(e)).upper()
        return "alert" if "ALERT" in reason else "unknown"
    except Exception:  # noqa: BLE001
        return "unknown"


def probe_all(targets, timeout: float = 6.0, workers: int = 16):
    """targets: [(key, ip, sni), ...] -> {(key, ip): result}"""
    results = {}

    def work(t):
        key, ip, sni = t
        return (key, ip), probe(ip, sni, timeout)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for (key, ip), res in pool.map(work, targets):
            results[(key, ip)] = res

    return results
