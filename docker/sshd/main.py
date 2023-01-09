# thanks:
# https://stackoverflow.com/questions/68768419/how-to-make-paramiko-ssh-server-execute-cammands
# https://stackoverflow.com/questions/62125669/how-can-i-implement-port-forwarding-in-a-paramiko-server

import os
import time
import select
import logging
import paramiko
import traceback
import socket, sys, threading
from pythonjsonlogger import jsonlogger
from logging.handlers import TimedRotatingFileHandler
from socketserver import ThreadingTCPServer, BaseRequestHandler
from lib.honeypot import resolve_host_port, config
from fakeshell.shell import FakeShell

DOMAIN_NAME = os.environ.get("DOMAIN_NAME")
handler = TimedRotatingFileHandler(
    f"/logs/sshd-{DOMAIN_NAME}.json", when="D", interval=1, backupCount=30, encoding="utf-8"
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

SSH_PORT = 22
LOGFILE_LOCK = threading.Lock()
HOST_KEY = paramiko.RSAKey.generate(2048)
HOST_KEY = paramiko.RSAKey(filename='/etc/server.key')

class ForwardClient(threading.Thread):
    daemon = True

    def __init__(self, dst, transport, chanid):
        threading.Thread.__init__(self)
        self.transport = transport
        self.dst_ip, self.dst_port = dst
        self.chanid = chanid
        # 転送先を動的に変更する
        host_port = self.dst_ip, self.dst_port
        if not self.dst_port in [53]:
            host_port = resolve_host_port(self.dst_ip, self.dst_port, path="", header_host="")
        self.socket = socket.create_connection(host_port)

    def run(self):
        try:
            while True:
                chan = self.transport.accept(1024)
                if chan == None:
                    continue

                if chan.get_id() == self.chanid:
                    break

            peer = self.socket.getpeername()
            try:
                self.tunnel(self.socket, chan)
            except Exception as e:
                logging.error(e)
        except Exception as e:
            logging.error(e)

    def tunnel(self, sock, chan, chunk_size=1024):
        while True:
            r, w, x = select.select([sock, chan], [], [])

            if sock in r:
                data = sock.recv(chunk_size)
                if len(data) == 0:
                    break
                chan.send(data)

            if chan in r:
                data = chan.recv(chunk_size)
                if len(data) == 0:
                    break
                sock.send(data)

        chan.close()
        sock.close()

class Server(paramiko.ServerInterface):
    def __init__(self, transport, client_address):
        self.transport = transport
        self.event = threading.Event()
        self.src_ip, self.src_port = client_address
        self.dst_ip, self.dst_port = "", -1
        self.username = ""
        self.password = ""
        self.command = ""
        self.chanid = -1

    def log_message(self, message):
        LOGFILE_LOCK.acquire()
        try:
            logger.info(
                message,
                extra={
                    "command": self.command,
                    "username": self.username,
                    "password": self.password,
                    "src_ip": self.src_ip,
                    "src_port": self.src_port,
                    "dst_ip": self.dst_ip,
                    "dst_port": self.dst_port,
                    "chanid": self.chanid,
                    "sensor": DOMAIN_NAME,
                },
            )
        except Exception as e:
            print(e)
        finally:
            LOGFILE_LOCK.release()

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        self.log_message(f"check_channel_request {kind}")
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED

        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.username = username
        self.password = password
        for auth in config["ssh"]["password_auth"]:
            user, passwd = auth.split(":")
            if username == user and password == passwd:
                self.log_message(f"Auth Successful: {username}")
                return paramiko.AUTH_SUCCESSFUL
        self.log_message(f"Auth Failed: {username}")
        return paramiko.AUTH_FAILED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        self.log_message(f"check_channel_pty_request {term, width, height, pixelwidth, pixelheight}")
        return False

    def check_channel_forward_agent_request(self, channel):
        self.log_message("check_channel_forward_agent_request")
        return False

    def check_channel_x11_request(self, channel, single_connection, auth_protocol, auth_cookie, screen_number):
        self.log_message("check_channel_x11_request")
        return False

    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
        self.dst_ip, self.dst_port = destination
        self.chanid = chanid
        self.log_message("check_channel_direct_tcpip_request")
        try:
            f = ForwardClient(destination, self.transport, chanid)
            f.start()
        except Exception as e:
            print(e)
        return paramiko.OPEN_SUCCEEDED

    def check_channel_exec_request(self, channel, command):
        command = command.decode()  # convert to string from bytes:
        self.command = command
        self.log_message("check_channel_exec_request")
        with FakeShell("/", exclude_dir=["/app", "/dev"]) as sh:
            for cmd_out in sh.run_command(command):
                channel.send(cmd_out)
        channel.send_exit_status(0)
        self.event.set()
        return True

    def check_channel_shell_request(self, channel):
        self.log_message("check_channel_shell_request")
        t = threading.Thread(target=self._execute_command, args=(channel,), daemon=True)
        t.start()
        return True

    def _execute_command(self, channel):
        banner = f'Last login: {time.strftime("%a %b %d %H:%M:%S %Y", time.localtime())} from {self.src_ip}\n\n'
        channel.send(banner)
        conn = socket.create_connection(("telnetd", 23))
        # telnetへ通信を転送する
        while True:
            r, w, x = select.select([channel, conn], [], [])

            if channel in r:
                data = channel.recv(1024)
                if len(data) == 0:
                    break
                self.command = data.decode()
                self.log_message("execution")
                if self.command in ["quit\n", "exit\n"]:
                    break
                conn.send(data)

            if conn in r:
                data = conn.recv(1024)
                if len(data) == 0:
                    break
                channel.send(data)

class SshHandler(BaseRequestHandler):
    def handle(self):
        connection = self.request
        try:
            t = paramiko.Transport(connection)
            t.local_version = config["ssh"].get("local_version", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3")
            t.set_gss_host(socket.getfqdn(""))
            t.load_server_moduli()
            t.add_server_key(HOST_KEY)

            server = Server(t, self.client_address)
            t.start_server(server=server)
            server.event.wait(300)
            t.close()

        except Exception as err:
            print(traceback.format_exc())

        try:
            t.close()
            connection.close()
        except Exception as err:
            print(traceback.format_exc())


ThreadingTCPServer.allow_reuse_address = True
with ThreadingTCPServer(("", SSH_PORT), SshHandler) as server:
    server.serve_forever()
