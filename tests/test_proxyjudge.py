from telnetlib import Telnet

host = 'proxyjudge.info'
pot_host = '127.0.0.1'
with Telnet(pot_host, 80) as tn:
    tn.write(f"CONNECT {host}:80 HTTP/1.1\r\n\r\n".encode())
    tn.read_until("Proxy-agent:".encode())
    tn.write(f"GET / HTTP/1.1\r\nHost: {host}\r\n".encode())
    tn.write(f"User-Agent: curl/7.84.0\r\n".encode())
    tn.write(f"Accept: */*\r\n\r\n".encode())
    body = tn.read_all()
    print(body.decode())
