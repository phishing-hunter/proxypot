from telnetlib import Telnet

# google以外はlocalhostに転送されるが
# 攻撃者は複数の多段プロキシを経由してGoogleに接続しているように見える
with Telnet('localhost', 80) as tn:
    print("proxy 1")
    tn.write(f"CONNECT bad-site1.com:8989 HTTP/1.0\r\n\r\n".encode())
    tn.read_until("Proxy-agent:".encode())
    print("proxy 2")
    tn.write(f"CONNECT bad-site2.com:8181 HTTP/1.0\r\n\r\n".encode())
    tn.read_until("Proxy-agent:".encode())
    print("proxy 3")
    tn.write(f"CONNECT bad-site3.com:6969 HTTP/1.0\r\n\r\n".encode())
    tn.read_until("Proxy-agent:".encode())
    print("proxy 4")
    tn.write(f"CONNECT bad-site4.com:1919 HTTP/1.0\r\n\r\n".encode())
    tn.read_until("Proxy-agent:".encode())
    # Googleに接続する
    tn.write(f"CONNECT www.google.com:80 HTTP/1.0\r\n\r\n".encode())
    tn.read_until("Proxy-agent:".encode())
    tn.write(f"GET / HTTP/1.0\r\n\r\n".encode())
    body = tn.read_all()
    print(len(body.decode()))
