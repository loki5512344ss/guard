#!/bin/sh
# Stub backend (TCP echo) на 127.0.0.1:25566 для стресс-теста edge ноды.
socat TCP-LISTEN:25566,fork,reuseaddr,bind=127.0.0.1 EXEC:'cat' &
exec rampart-core --config /etc/rampart/config.toml
