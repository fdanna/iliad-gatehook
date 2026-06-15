FROM python:3.12-slim

WORKDIR /opt/gatehook-admin

COPY admin/admin_server.py /opt/gatehook-admin/admin_server.py

ENTRYPOINT ["python", "-u", "/opt/gatehook-admin/admin_server.py"]
