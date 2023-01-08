FROM python:3.9

RUN apt-get update && apt-get install openssl && \
    openssl genrsa -out /etc/server.key 4096

RUN mkdir /logs
COPY ./sshd /app
WORKDIR /app

RUN pip3 install -r requirements.txt

COPY ./common/lib/honeypot.py /app/lib/
COPY ./common/honeypot.yaml /app/
ENTRYPOINT ["/app/entrypoint.sh"]
