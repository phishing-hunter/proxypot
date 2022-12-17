FROM python:3.9

COPY ./requirements.txt .
RUN pip3 install -r requirements.txt
RUN mkdir /logs

COPY ./content /content
COPY ./app /app
COPY ./honeypot.yaml /
COPY ./*.sh /
WORKDIR /app
ENTRYPOINT ["/entrypoint.sh"]
