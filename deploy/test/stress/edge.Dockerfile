FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends socat ca-certificates && rm -rf /var/lib/apt/lists/*
COPY rampart-core /usr/local/bin/rampart-core
COPY start.sh /start.sh
RUN chmod +x /start.sh
EXPOSE 25565 9090
CMD ["/start.sh"]
