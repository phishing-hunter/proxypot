import os
import time
import yaml

config = {}
with open("/app/honeypot.yaml", "r") as f:
    config = yaml.safe_load(f)

def check_path(path):
    whitelist_path_keyword = config["proxy"]["whitelist_path_keywords"]
    for keyword in whitelist_path_keyword:
        if path.find(keyword) != -1:
            return True
    return False

def check_domain(domain):
    whitelist_domain_keyword = config["proxy"]["whitelist_domain_keywords"]
    if domain is None:
        return False
    for keyword in whitelist_domain_keyword:
        if domain.find(keyword) != -1:
            return True
    return False


def get_port_range(port_range_list):
    ports = []
    for port_range in port_range_list:
        pr = list(map(int, port_range.split("-")))
        ports += list(range(pr[0], pr[1]))
    return ports

def resolve_host_port(src_host, src_port, path="", header_host=""):
    proxy = False
    host_port = src_host, src_port
    # 接続先のポート番号によってはブロックする
    port_range = config["proxy"]["drop"].get("port_range", [])
    if src_port in get_port_range(port_range):
        return 0

    # 転送ルールを使って宛先を書き換える
    for name in config["proxy"]["port_forward"].keys():
        pot = config["proxy"]["port_forward"][name]
        target = pot["target"]
        if src_port in get_port_range(pot.get("src_port_range", [])):
            dst_port = pot.get("dst_port")
            if dst_port:
                host_port = name, dst_port
            else:
                host_port = name, src_port
            proxy = True
            break

        if src_port in pot.get("src_ports", []):
            dst_port = pot.get("dst_port")
            if dst_port:
                host_port = target, dst_port
            else:
                host_port = target, src_port
            proxy = True
            break
    # ホワイトリスト以外はローカルに転送する
    if (
        not proxy
        and not check_domain(src_host)
        and not check_domain(header_host)
        and not check_path(path)
    ):
        ssl_port_forward = config["proxy"]["ssl_port_forward"].get("port_range", [443])
        if host_port[1] in ssl_port_forward:
            host_port = "socat", 443
        else:
            host_port = "httpd", 80
    return host_port
