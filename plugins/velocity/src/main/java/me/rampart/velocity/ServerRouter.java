package me.rampart.velocity;

import com.velocitypowered.api.proxy.server.RegisteredServer;

import java.util.Optional;

public class ServerRouter {

    private final ServerRegistry registry;

    public ServerRouter(ServerRegistry registry) {
        this.registry = registry;
    }

    public Optional<RegisteredServer> routeServer(String domain) {
        return registry.getNextServer();
    }
}
