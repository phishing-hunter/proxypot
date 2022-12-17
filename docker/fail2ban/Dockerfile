FROM ubuntu:22.04

RUN DEBIAN_FRONTEND=noninteractive apt-get update -y && \
    apt-get install -y --no-install-recommends \
    curl \
    fail2ban \
    iptables \
    ipset \
    python3 \
    python3-pip \
    python3-dev \
    whois \
    tzdata \
    && rm -rf /var/lib/apt/lists/* && \
    pip3 install --upgrade pip && \
    pip3 install pyinotify && \
    rm -rf /etc/fail2ban/jail.d

RUN sed -i -e "s/loglevel = INFO/loglevel = WARN/g" /etc/fail2ban/fail2ban.conf
COPY ./filter.d/* /etc/fail2ban/filter.d/
COPY jail.local /etc/fail2ban/jail.local

COPY ./*.sh /
ENTRYPOINT ["/entrypoint.sh"]
