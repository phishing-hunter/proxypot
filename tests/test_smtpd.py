import smtplib
import socks
from email.mime.text import MIMEText

to_email = "test@hoge.com"
from_email = "test@fuga.com"

message = "ほげ"
msg = MIMEText(message, "html")
msg["Subject"] = "test"
msg["To"] = to_email
msg["From"] = from_email

# proxy経由でemailを送信する
socks.setdefaultproxy(socks.HTTP, 'localhost', 80)
socks.wrapmodule(smtplib)

# smtpパスワードなしで送信
server = smtplib.SMTP("127.0.0.1", 25)
server.set_debuglevel(2)
server.send_message(msg)
server.quit()
