FROM python:3.9

RUN mkdir /logs
COPY ./telnetd /app
WORKDIR /app

RUN pip3 install -r requirements.txt

COPY ./common/lib/honeypot.py /app/lib/
COPY ./common/honeypot.yaml /app/
ENTRYPOINT ["/app/entrypoint.sh"]
