package me.rampart.velocity;

import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.player.ServerPreConnectEvent;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import org.slf4j.Logger;

import java.util.Optional;

public class ServerRouter {

    private static final double TPS_DEAD = 12.0;

    private final ServerRegistry registry;
    private final Logger logger;

    public ServerRouter(ServerRegistry registry, Logger logger) {
        this.registry = registry;
        this.logger = logger;
    }

    @Subscribe
    public void onServerPreConnect(ServerPreConnectEvent event) {
        if (event.getResult().getServer().isPresent()) {
            return;
        }
        String domain = event.getPlayer().getVirtualHost()
            .map(vh -> vh.getHostString().split("\0")[0])
            .orElse("");

        Optional<RegisteredServer> target = routeServer(domain);
        if (target.isPresent()) {
            event.setResult(ServerPreConnectEvent.ServerResult.allowed(target.get()));
        } else {
            logger.warn("No available backend server for {} (domain: {})",
                event.getPlayer().getRemoteAddress(), domain);
        }
    }

    public Optional<RegisteredServer> routeServer(String domain) {
        for (RegisteredServer server : registry.getCachedServers()) {
            double tps = registry.getServerTps(server.getServerInfo().getName());
            if (tps >= TPS_DEAD) {
                return Optional.of(server);
            }
        }
        return registry.getNextServer();
    }
}
