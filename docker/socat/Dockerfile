FROM python:3.9

RUN apt-get update && apt-get install -y supervisor socat netcat
COPY ./socat/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

COPY ./socat/socat /socat
COPY ./socat/*.sh /
ENTRYPOINT ["/entrypoint.sh"]
