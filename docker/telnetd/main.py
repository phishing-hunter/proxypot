import os
import logging
from fakeshell.shell import FakeShell
from socketserver import TCPServer, StreamRequestHandler
from socketserver import ThreadingTCPServer, BaseRequestHandler


class Handler(StreamRequestHandler):

    def _get_ps1(self):
        cwd = os.getcwd()
        cwd = "~" if cwd == os.environ["HOME"] else cwd
        ps1 = f"[root@localhost {cwd}]# "
        return ps1

    def handle(self):
        stdin = self.request.makefile('r', encoding='utf-8')
        stdout = self.request.makefile('w', encoding='utf-8')

        command = ""
        with FakeShell(cwd="/", home="/", exclude_dir=["/app", "/logs", "/dev"]) as sh:
            stdout.write(self._get_ps1())
            stdout.flush()
            for command in stdin:
                try:
                    if command == "\n":
                        stdout.write("")
                        stdout.flush()
                        continue
                    if command in ["quit\n", "exit\n"]:
                        stdout.write("")
                        stdout.flush()
                        break
                    for cmd_out in sh.run_command(command):
                        stdout.write(cmd_out)
                        stdout.flush()
                except:
                    logging.exception("command execution error")
                finally:
                    stdout.write(self._get_ps1())
                    stdout.flush()


        stdin.close()
        stdout.close()

ThreadingTCPServer.allow_reuse_address = True
with ThreadingTCPServer(("", 23), Handler) as server:
    server.serve_forever()
