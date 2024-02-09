from . import ( http
    , https
    , hysteria
    , hysteria2
    , socks
    , ss
    , ssr
    , trojan
    , tuic
    , vless
    , vmess
    , wg
    )

parsers_list = [
    "http",
    "https",
    "hysteria",
    "hysteria2",
    "socks",
    "ss",
    "ssr",
    "trojan",
    "tuic",
    "vless",
    "vmess",
    "wg"]

def module_to_dict():
    import sys
    module = sys.modules[__name__]
    return { n: getattr(module, n) for n in parsers_list }

__all__ = parsers_list + ["module_to_dict", "clash2base64"]
