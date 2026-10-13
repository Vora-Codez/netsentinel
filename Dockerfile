FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    NETSENTINEL_HOME=/data NETSENTINEL_HOST=0.0.0.0 NETSENTINEL_PORT=8765
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY netsentinel ./netsentinel
VOLUME /data
EXPOSE 8765
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request,os;urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('NETSENTINEL_PORT','8765')+'/api/ping',timeout=4)"
# Runs as root inside the container so Scapy can open raw sockets when NET_RAW is granted.
# docker-compose.yml drops every other capability. Without NET_RAW you can set `user: "10001"`.
CMD ["python", "-m", "netsentinel", "serve"]
