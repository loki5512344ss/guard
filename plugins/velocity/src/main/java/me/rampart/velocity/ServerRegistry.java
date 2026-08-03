package me.rampart.velocity;

import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import com.velocitypowered.api.proxy.server.ServerInfo;
import org.slf4j.Logger;
import redis.clients.jedis.Jedis;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

public class ServerRegistry {

    private final ProxyServer proxyServer;
    private final Logger logger;
    private final String redisUrl;
    private final AtomicInteger counter = new AtomicInteger(0);
    private final ConcurrentHashMap<String, Double> tpsCache = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> serverDomains = new ConcurrentHashMap<>();
    private volatile List<RegisteredServer> cachedServers = new ArrayList<>();

    public ServerRegistry(ProxyServer proxyServer, Logger logger, String redisUrl) {
        this.proxyServer = proxyServer;
        this.logger = logger;
        this.redisUrl = redisUrl;
    }

    public void startSync() {
        loadAndUpdateServers();
        proxyServer.getScheduler()
            .buildTask(this, this::loadAndUpdateServers)
            .repeat(30, TimeUnit.SECONDS)
            .schedule();
    }

    void loadAndUpdateServers() {
        List<ServerInfo> redisServers = loadServersFromRedis();
        Set<String> redisNames = redisServers.stream()
            .map(ServerInfo::getName)
            .collect(Collectors.toSet());
        Set<String> registeredNames = proxyServer.getAllServers().stream()
            .map(s -> s.getServerInfo().getName())
            .collect(Collectors.toSet());

        int registered = 0;
        int unregistered = 0;

        for (ServerInfo info : redisServers) {
            if (!registeredNames.contains(info.getName())) {
                proxyServer.registerServer(info);
                registered++;
            }
        }

        for (String name : registeredNames) {
            if (!redisNames.contains(name)) {
                proxyServer.getServer(name).ifPresent(s ->
                    proxyServer.unregisterServer(s.getServerInfo()));
                serverDomains.remove(name);
                unregistered++;
            }
        }

        List<RegisteredServer> servers = redisServers.stream()
            .map(info -> proxyServer.getServer(info.getName()).orElse(null))
            .filter(Objects::nonNull)
            .collect(Collectors.toList());

        cachedServers = servers;

        logger.info("Server sync complete: {} registered, {} unregistered, {} online",
            registered, unregistered, servers.size());
    }

    List<ServerInfo> loadServersFromRedis() {
        List<ServerInfo> servers = new ArrayList<>();
        try (Jedis jedis = new Jedis(redisUrl)) {
            Set<String> keys = jedis.keys("rampart:servers:*");
            for (String key : keys) {
                String json = jedis.get(key);
                if (json == null || json.isEmpty()) continue;
                try {
                    String name = extractJsonString(json, "name");
                    String ip = extractJsonString(json, "ip");
                    if (name == null || ip == null) continue;
                    int port = extractJsonInt(json, "port");
                    if (port <= 0) continue;
                    String status = extractJsonString(json, "status");
                    if (!"online".equals(status)) continue;
                    double tps = extractJsonDouble(json, "tps");
                    tpsCache.put(name, tps);
                    String domain = extractJsonString(json, "domain");
                    if (domain != null && !domain.isEmpty()) {
                        serverDomains.put(name, domain.trim());
                    } else {
                        serverDomains.remove(name);
                    }
                    servers.add(new ServerInfo(name, InetSocketAddress.createUnresolved(ip, port)));
                } catch (Exception e) {
                    logger.warn("Failed to parse server data for key {}: {}", key, e.getMessage());
                }
            }
        } catch (Exception e) {
            logger.warn("Failed to connect to Redis at {}: {}", redisUrl, e.getMessage());
        }
        return servers;
    }

    public Optional<RegisteredServer> getNextServer() {
        List<RegisteredServer> servers = cachedServers;
        if (servers.isEmpty()) return Optional.empty();
        int index = Math.abs(counter.getAndIncrement() % servers.size());
        return Optional.ofNullable(servers.get(index));
    }

    public List<RegisteredServer> getCachedServers() {
        return cachedServers;
    }

    public double getServerTps(String name) {
        return tpsCache.getOrDefault(name, 20.0);
    }

    public String getServerDomain(String name) {
        return serverDomains.get(name);
    }

    private static String extractJsonString(String json, String key) {
        String search = "\"" + key + "\":\"";
        int start = json.indexOf(search);
        if (start < 0) return null;
        start += search.length();
        int end = json.indexOf("\"", start);
        if (end < 0) return null;
        return json.substring(start, end);
    }

    private static int extractJsonInt(String json, String key) {
        String search = "\"" + key + "\":";
        int start = json.indexOf(search);
        if (start < 0) return -1;
        start += search.length();
        int end = start;
        while (end < json.length() && Character.isDigit(json.charAt(end))) {
            end++;
        }
        if (end == start) return -1;
        try {
            return Integer.parseInt(json.substring(start, end));
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private static double extractJsonDouble(String json, String key) {
        String search = "\"" + key + "\":";
        int start = json.indexOf(search);
        if (start < 0) return 20.0;
        start += search.length();
        int end = start;
        while (end < json.length() && (Character.isDigit(json.charAt(end)) || json.charAt(end) == '.')) {
            end++;
        }
        if (end == start) return 20.0;
        try {
            return Double.parseDouble(json.substring(start, end));
        } catch (NumberFormatException e) {
            return 20.0;
        }
    }
}
