# syntax=docker/dockerfile:1
FROM python:3.13-slim-bookworm

ARG APP_VERSION=1.2.3
LABEL org.opencontainers.image.title="NetAtlas" \
      org.opencontainers.image.description="Air-gap friendly multi-site network inventory and MobaXterm exporter" \
      org.opencontainers.image.version="${APP_VERSION}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap openssh-client ca-certificates libcap2-bin \
    && setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 netatlas \
    && useradd --system --uid 10001 --gid netatlas --home-dir /app --shell /usr/sbin/nologin netatlas

WORKDIR /app
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir --requirement requirements.txt
COPY --chown=netatlas:netatlas backend.py ./backend.py
COPY --chown=netatlas:netatlas web ./web
RUN mkdir -p /app/data && chown netatlas:netatlas /app/data

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NETATLAS_DATA_DIR=/app/data
USER netatlas
EXPOSE 8765
VOLUME ["/app/data"]
HEALTHCHECK --interval=20s --timeout=4s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/api/health', timeout=3)"]
CMD ["python", "backend.py", "--host", "0.0.0.0", "--port", "8765", "--no-browser"]
