import os
import time
import yaml
import socket
import select
import random
import click
import requests
import logging
from uuid import uuid4
from pythonjsonlogger import jsonlogger
from logging.handlers import TimedRotatingFileHandler
from http.server import HTTPServer
from http.server import BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, urlunparse, unquote

DOMAIN_NAME = os.environ.get("DOMAIN_NAME")
HONEYPOT_IP = os.environ.get("HONEYPOT_IP")
handler = TimedRotatingFileHandler(
    f"/logs/httpd-{DOMAIN_NAME}.json", when="D", interval=1, backupCount=30, encoding="utf-8"
)

handler.setFormatter(
    jsonlogger.JsonFormatter(
        fmt="%(asctime)s %(src_ip)-15s %(dst_ip)-15s %(src_port)d %(dst_port)d %(levelname)-7s %(message)s",
        json_ensure_ascii=False,
    )
)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(handler)

config = {}
with open("/honeypot.yaml", "r") as f:
    config = yaml.safe_load(f)

MAX_RECV_SIZE = config["httpd"]["proxy"].get("max_recv_size", -1)
SOCKET_TIMEOUT = config["httpd"].get("socket_timeout", 20)

SERVER_VERSION = config["httpd"].get("server_version", "nginx/1.4.6")
SYS_VERSION = config["httpd"].get("sys_version", "(Ubuntu)")

sessions = {}


def content_read(filename):
    try:
        fp = open(filename)
    except:
        return ""
    content = fp.read()
    fp.close()
    return content


def fake_proxy_checker(path, ip, port):
    content, content_type = "", ""
    result = False
    if path != "/" and len(path) < 10:
        content = content_read("/content/azenv.html")
        content = content.replace("__REMOTE_ADDR__", HONEYPOT_IP).replace(
            "__REMOTE_PORT__", str(port)
        )
        content_type = "text/html; charset=ISO-8859-1"
        result = True
    return result, content, content_type


def ext_checker(path):
    content_type = None
    for ext in [".png", ".gif", ".jpg"]:
        if path.endswith(ext):
            content = ""
            content_type = f"image/{ext}"
            break
    return content_type


def keyword_matcher(path, keywords):
    for keyword in keywords:
        if path.find(keyword) != -1:
            return True
    return False


def simple_echo_vuln_checker(body):
    if body.find("echo") != -1:
        return True
    return False


def fake_content(self):
    method = self.command
    path = self.path
    ip, port = self.client_address

    functions = config["httpd"]["response"][method.lower()].get("functions", [])
    default = config["httpd"]["response"][method.lower()]["default"]

    content = default["content"]
    content_type = default["type"]

    for func in functions:
        if func["function"] == "simple_echo_vuln_checker":
            if simple_echo_vuln_checker(self.post_body):
                content_type = func.get("type", default["type"])
                return self.post_body, content_type
        if func["function"] == "keyword_matcher":
            keywords = func["keywords"]
            if keyword_matcher(path, keywords):
                content = (
                    content_read(func.get("file")) if func.get("file") else func.get("content", "")
                )
                content_type = func.get("type", default["type"])
                return content, content_type
        if func["function"] == "ext_checker":
            res = ext_checker(path)
            if res is not None:
                return "", res
        if func["function"] == "proxy_checker":
            res, con, typ = fake_proxy_checker(path, ip, port)
            if res:
                return con, typ

    return content, content_type


def check_path(path):
    whitelist_path_keyword = config["httpd"]["proxy"]["whitelist_path_keywords"]
    for keyword in whitelist_path_keyword:
        if path.find(keyword) != -1:
            return True
    return False


def check_domain(domain):
    whitelist_domain_keyword = config["httpd"]["proxy"]["whitelist_domain_keywords"]
    if domain is None:
        return False
    for keyword in whitelist_domain_keyword:
        if domain.find(keyword) != -1:
            return True
    return False


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        global sessions
        timeout = SOCKET_TIMEOUT
        BaseHTTPRequestHandler.setup(self)
        self.request.settimeout(timeout)
        self.host_port = "", 80
        self.post_body = ""
        self.post_size = 0
        # Proxyを経由している場合はIPとポート番号からセッションIDを確認する
        ip, port = self.client_address
        key = f"{ip}:{port}"
        session = sessions.get(key, {})
        self.session_id = session.get("id", uuid4().hex)
        self.src_ip = session.get("src_ip", ip)
        self.src_port = session.get("src_port", port)
        try:
            del sessions[key]
        except:
            pass

    def log_error(self, format, *args):
        ip, port = self.client_address
        self._logger(logger.error, f"{format%args}")

    def log_debug(self, format, *args):
        self._logger(logger.debug, f"{format%args}")

    def log_message(self, format, *args):
        self._logger(logger.info, f"{format%args}")

    def _logger(self, logger_func, message):
        ip, port = self.client_address
        method, path = "", ""
        headers = {}
        try:
            method = self.command
            path = unquote(self.path)
            headers = dict(self.headers)
        except:
            pass
        logger_func(
            message,
            extra={
                "method": method,
                "headers": headers,
                "body": self.post_body,
                "size": self.post_size,
                "src_ip": self.src_ip,
                "src_port": self.src_port,
                "dst_ip": self.host_port[0],
                "dst_port": self.host_port[1],
                "path": path,
                "sensor": DOMAIN_NAME,
                "session": self.session_id,
            },
        )

    def _port_range(self, port_range_list):
        ports = []
        for port_range in port_range_list:
            pr = list(map(int, port_range.split("-")))
            ports += list(range(pr[0], pr[1]))
        return ports

    def _connect_to(self, netloc, sock):
        result = 0
        try:
            i = netloc.find(":")
            host_port = (netloc[:i], int(netloc[i + 1 :])) if i >= 0 else (netloc, 80)
            self.host_port = host_port
        except Exception as e:
            return 0

        proxy = False
        # 接続先のポート番号によってはブロックする
        src_port = host_port[1]
        port_range = config["httpd"]["proxy"]["drop"].get("port_range", [])
        if src_port in self._port_range(port_range):
            return 0

        # 転送ルールを使って宛先を書き換える
        for name in config["httpd"]["proxy"]["port_forward"].keys():
            pot = config["httpd"]["proxy"]["port_forward"][name]
            target = pot["target"]
            if src_port in self._port_range(pot.get("src_port_range", [])):
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
            and not check_domain(host_port[0])
            and not check_domain(self.headers.get("Host"))
            and not check_path(self.path)
        ):
            ssl_port_forward = config["httpd"]["proxy"]["ssl_port_forward"].get("port_range", [443])
            if host_port[1] in ssl_port_forward:
                host_port = "socat", 443
            else:
                host_port = "httpd", 80

        # 宛先に接続する
        try:
            global sessions
            sock.connect(host_port)
            ip, port = sock.getsockname()
            key = f"{ip}:{port}"
            sessions[key] = {
                "id": self.session_id,
                "src_ip": self.src_ip,
                "src_port": self.src_port,
            }
            self.log_debug(f"{netloc} -> {host_port[0]}:{host_port[1]}")
            result = 1
        except Exception as e:
            self.send_error(404, "not found")
        return result

    def _read_write(self, sock, max_idling):
        address = self.client_address
        iw, ow = [self.connection, sock], []
        count = 0
        size = 0

        class GetOutOfLoop(Exception):
            pass

        try:
            while True:
                count += 1
                (ins, _, exs) = select.select(iw, ow, iw, 3)
                if exs:
                    raise GetOutOfLoop
                if not ins and count == max_idling:
                    raise GetOutOfLoop
                for i in ins:
                    out = self.connection if i is sock else sock
                    data = i.recv(1024 * 8)
                    resv_len = len(data)
                    size += resv_len
                    if MAX_RECV_SIZE != -1 and size > MAX_RECV_SIZE:
                        raise GetOutOfLoop
                    if resv_len == 0:
                        raise GetOutOfLoop
                    if data:
                        out.send(data)
                        count = 0
        except:
            pass
        return size

    def _mod_proxy(self):
        method = self.command
        self.connection.settimeout(SOCKET_TIMEOUT)
        if method != "CONNECT":
            (scm, netloc, path, params, query, fragment) = urlparse(self.path)
            if not (scm == "http" or scm == "https") or not netloc:
                return 0
        else:
            netloc = self.path
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(SOCKET_TIMEOUT)
            connect = self._connect_to(netloc, sock)
            if connect:
                self.log_message(f"proxy {method} {netloc}")
                try:
                    del self.headers["Proxy-Connection"]
                except:
                    pass
                if method != "CONNECT":
                    path = "/" if path == "" else path
                    sock.send(
                        f"{self.command} {urlunparse(('', '', path, params, query, ''))} {self.request_version}\r\n".encode()
                    )
                    for key_val in self.headers.items():
                        sock.send(f"%s: {key_val}\r\n".encode())
                    sock.send("\r\n".encode())
                if method == "CONNECT":
                    self.server_version = SERVER_VERSION
                    self.sys_version = SYS_VERSION
                    self.wfile.write(
                        f"{self.protocol_version} 200 Connection Established\r\n".encode()
                    )
                    self.wfile.write(f"Proxy-agent: {self.version_string()}\r\n\r\n".encode())
                size = self._read_write(sock, config["httpd"]["proxy"]["max_connections"])
        finally:
            sock.close()
            self.connection.close()
        return 1

    def do_CONNECT(self):
        self._mod_proxy()

    def do_GET(self):
        if self._mod_proxy() == 1:
            return
        body, content_type = fake_content(self)
        self.server_version = SERVER_VERSION
        self.sys_version = SYS_VERSION
        self.protocol_version = self.request_version
        self.send_response(200)
        self.send_header("Content-Length", len(body))
        self.send_header("Connection", "close")
        self.send_header("Content-Type", content_type)
        self.end_headers()
        self.wfile.write(body.encode())
        # self.connection.close()

    def do_POST(self):
        if self._mod_proxy() == 1:
            return
        if "content-length" in self.headers:
            try:
                content_len = int(self.headers["content-length"])
                body = self.rfile.read(content_len).decode()
                self.rfile.close()
                self.post_size = len(body)
                if content_len < config["httpd"]["post"]["max_payload_size"]:
                    self.post_body = body
            except Exception as e:
                print(e)
        body, content_type = fake_content(self)
        self.server_version = SERVER_VERSION
        self.sys_version = SYS_VERSION
        self.protocol_version = self.request_version
        self.send_response(200)
        self.send_header("Content-Length", len(body))
        self.send_header("Connection", "close")
        self.send_header("Content-Type", content_type)
        self.end_headers()
        self.wfile.write(body.encode())
        # self.connection.close()

    def do_HEAD(self):
        self.server_version = SERVER_VERSION
        self.sys_version = SYS_VERSION
        self.send_response(200)
        self.send_header("Content-Length", 0)
        self.end_headers()

    def do_OPTIONS(self):
        self.server_version = SERVER_VERSION
        self.sys_version = SYS_VERSION
        self.send_response(200)
        self.send_header("Content-Length", 0)
        self.send_header("Content-type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header(
            "Access-Control-Allow-Headers",
            "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token,X-Amz-User-Agent,X-Amzn-Trace-Id",
        )
        self.end_headers()

    def do_PUT(self):
        self.server_version = SERVER_VERSION
        self.sys_version = SYS_VERSION
        self.send_response(200)
        self.send_header("Content-Length", 0)
        self.end_headers()

    def do_DELETE(self):
        self.server_version = SERVER_VERSION
        self.sys_version = SYS_VERSION
        self.send_response(200)
        self.send_header("Content-Length", 0)
        self.end_headers()


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    pass


@click.command()
@click.option("--port", help="port", type=int)
def main(port):
    host = "0.0.0.0"
    server = ThreadingHTTPServer((host, port), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
