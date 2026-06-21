FROM python:3.12-slim

WORKDIR /opt/gatehook

COPY scripts/gatehook.py /opt/gatehook/gatehook.py
COPY scripts/healthcheck.py /opt/gatehook/healthcheck.py
COPY scripts/whitelist.enabled /opt/gatehook/whitelist.enabled
COPY scripts/whitelist.txt /opt/gatehook/whitelist.txt

ENTRYPOINT ["python", "-u", "/opt/gatehook/gatehook.py"]
