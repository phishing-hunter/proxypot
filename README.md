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
cp honeypot.yaml.sample docker/common/honeypot.yaml
```

### サーバの起動
```
$ docker-compose up -d --build httpd sshd telnetd socat
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

