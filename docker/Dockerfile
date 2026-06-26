# Dockerfile
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y python3 python3-pip iproute2 tcpdump
COPY src/ /app/
COPY scripts/ /scripts/
COPY www/ /app/www/
COPY dns/hosts.txt /app/hosts.txt
WORKDIR /app