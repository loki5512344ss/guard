package me.rampart.velocity;

import com.google.inject.Inject;
import com.velocitypowered.api.event.EventManager;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.proxy.ProxyServer;
import org.slf4j.Logger;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@Plugin(
    id = "rampart",
    name = "Rampart",
    version = "0.1.0",
    description = "HMAC hostname verification + domain whitelist + Redis server registry for Rampart",
    authors = {"loki"}
)
public class RampartVelocity {

    private final Logger logger;
    private final ServerRegistry serverRegistry;

    @Inject
    public RampartVelocity(ProxyServer server, Logger logger) {
        this.logger = logger;

        String secret = System.getenv("RAMPART_HMAC_SECRET");
        List<String> allowed = loadDomainWhitelist();

        if (!allowed.isEmpty()) {
            logger.info("Domain whitelist: {} domains loaded", allowed.size());
            server.getEventManager().register(this, new DomainCheckListener(logger, allowed));
        } else {
            logger.warn("RAMPART_ALLOWED_DOMAINS not set — domain check disabled");
        }

        if (secret != null && !secret.isEmpty()) {
            logger.info("HMAC verification enabled");
            server.getEventManager().register(this, new HmacCheckListener(logger, secret));
        } else {
            logger.warn("RAMPART_HMAC_SECRET not set — HMAC verification disabled");
        }

        String redisUrl = System.getenv("RAMPART_REDIS_URL");
        if (redisUrl == null || redisUrl.isEmpty()) {
            redisUrl = "redis://127.0.0.1:6379/0";
        }

        serverRegistry = new ServerRegistry(server, logger, redisUrl);
        serverRegistry.startSync();
        logger.info("Server registry sync started with Redis at {}", redisUrl);
    }

    private List<String> loadDomainWhitelist() {
        String env = System.getenv("RAMPART_ALLOWED_DOMAINS");
        if (env == null || env.isEmpty()) return Collections.emptyList();
        return Arrays.stream(env.split(","))
            .map(String::trim)
            .filter(s -> !s.isEmpty())
            .toList();
    }
}
