import smtplib
import socks
import ssl
from email.mime.text import MIMEText

to_email = "test@hoge.com"
from_email = "test@fuga.com"

message = "test message"
msg = MIMEText(message, "html")
msg["Subject"] = "test"
msg["To"] = to_email
msg["From"] = from_email

# proxy経由でemailを送信する
socks.setdefaultproxy(socks.HTTP, 'localhost', 80)
socks.wrapmodule(smtplib)


smtp_account_id = 'user'
smtp_account_pass = 'password'
context = ssl.create_default_context()
host = '127.0.0.1'
server = smtplib.SMTP(host, 587)
server.set_debuglevel(2) 

server.ehlo()
server.starttls()
server.ehlo()
server.login(smtp_account_id, smtp_account_pass)

server.send_message(msg)
server.quit()
