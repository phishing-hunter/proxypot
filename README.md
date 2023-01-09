# openproxy honeypot

OpenProxyのように振る舞うハニーポット  
ほとんどの通信がlocalhostへ転送されます  

[説明スライド](https://speakerdeck.com/tatsui/openproxyxing-hanihotuto-proxypot)

ログ解析ツールは[こちら](https://github.com/phishing-hunter/proxypot-analyzer)

## HTTPプロキシサーバ
[![asciicast](https://asciinema.org/a/550329.svg)](https://asciinema.org/a/550329)

## SSHプロキシサーバ
[![asciicast](https://asciinema.org/a/550328.svg)](https://asciinema.org/a/550328)

## セットアップ方法
### 証明書の取得
はじめに証明書の取得を行います。  
ハニーポットがグローバルIPアドレスを持っていない場合は手順をスキップしてください。  
```
$ docker-compose up -d nginx
$ docker-compose run --rm certbot certonly --webroot -w /var/www/html -d honeypot.local --agree-tos -m example@honeypot.local
```

### 設定ファイルをコピー
```bash
cp env.template .env
cp honeypot.yaml.sample docker/common/honeypot.yaml
```

### サーバの起動
```
$ docker-compose up -d --build httpd sshd telnetd socat
```

## 動作確認
HTTPサーバの動作を確認します。
```bash
curl -XGET localhost:8080
curl -XPOST localhost:8080 -d '{"hoge": "hoo"}'
curl -XPOST localhost:8080 -d "exploit payload > echo hoge| md5sum"
curl -XGET -x http://127.0.0.1:8080 http://example.com
curl -XGET -x http://127.0.0.1:8080 http://example.com/login
curl -XPOST -x http://127.0.0.1:8080 http://example.com -d 'hoge=foo'
```
以下のファイルにログが記録されます。
```bash
cat /data/httpd-honeypot.local.json
{"asctime": "2023-01-08 17:40:00,025", "src_ip": "172.25.0.1", "dst_ip": "example.com", "src_port": 60948, "dst_port": 80, "levelname": "INFO", "message": "proxy POST example.com", "method": "POST", "headers": {"Host": "example.com", "User-Agent": "curl/7.81.0", "Accept": "*/*", "Proxy-Connection": "Keep-Alive", "Content-Length": "8", "Content-Type": "application/x-www-form-urlencoded"}, "body": "", "size": 0, "path": "http://example.com/", "sensor": "honeypot.local", "session": "dfb255d8a50942c19f9e55f5648dc85a"}
```

踏み台SSHサーバに接続(パスワード: password)
```bash
ssh root@127.0.0.1 -p 2222 -D 9050
```

SSHサーバを経由してifconfig.ioへ接続する
```bash
curl -x socks5h://127.0.0.1:9050 http://ifconfig.io
```

以下のファイルにログが記録されます。
```bash
cat /data/sshd-honeypot.local.json
{"asctime": "2023-01-08 17:23:35,467", "src_ip": "172.25.0.1", "dst_ip": "ifconfig.io", "src_port": 60424, "dst_port": 80, "levelname": "INFO", "message": "check_channel_direct_tcpip_request", "command": "", "username": "root", "password": "password", "chanid": 1, "sensor": "honeypot.local"}
```

### Proxy Checker
ハニーポットを起動したら以下のサイトでチェックします。  

### http
* http://www.cybersyndrome.net/pc.cgi
* https://proxy6.net/en/checker
* https://proxyscrape.com/online-proxy-checker
* https://hidester.com/proxychecker/
* https://checkerproxy.net/
* https://www.proxychecker.ge/

### smtp
* https://mxtoolbox.com/diagnostic.aspx
* http://www.antispam-ufrj.pads.ufrj.br/test-relay.html

