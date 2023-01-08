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
from lib.honeypot import resolve_host_port, config
from fakeshell.shell import FakeShell

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

MAX_RECV_SIZE = config["proxy"].get("max_recv_size", -1)
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
        content = content_read("/app/content/azenv.html")
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


def run_fake_shell(body):
    results = []
    if body.find("echo") != -1:
        with FakeShell("/", exclude_dir=["/scripts", "/dev"]) as sh:
            for cmd_out in sh.run_command(body):
                results.append(cmd_out)
    else:
        return "", False
    return "\n".join(results), True


def fake_content(self):
    method = self.command
    path = self.path
    ip, port = self.client_address

    functions = config["httpd"]["response"][method.lower()].get("functions", [])
    default = config["httpd"]["response"][method.lower()]["default"]

    content = default["content"]
    content_type = default["type"]

    for func in functions:
        if func["function"] == "fake_shell":
            res_content, ret = run_fake_shell(self.post_body)
            if ret:
                content = res_content
                content_type = "text/plain"
                return content, content_type
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

    def _connect_to(self, netloc, sock):
        result = 0
        try:
            i = netloc.find(":")
            host_port = (netloc[:i], int(netloc[i + 1 :])) if i >= 0 else (netloc, 80)
            self.host_port = host_port
        except Exception as e:
            return 0

        # 転送先を動的に変更する
        src_host, src_port = host_port
        host_port = resolve_host_port(src_host, src_port, path=self.path, header_host=self.headers.get("Host"))

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
                size = self._read_write(sock, config["proxy"]["max_connections"])
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
