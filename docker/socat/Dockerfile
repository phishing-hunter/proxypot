FROM python:3.9

RUN apt-get update && apt-get install -y supervisor socat netcat
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

COPY ./socat /socat
COPY ./*.sh /
ENTRYPOINT ["/entrypoint.sh"]
