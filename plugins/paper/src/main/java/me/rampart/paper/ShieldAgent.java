package me.rampart.paper;

import org.bukkit.Bukkit;
import org.bukkit.scheduler.BukkitRunnable;
import redis.clients.jedis.Jedis;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.concurrent.ThreadLocalRandom;

public class ShieldAgent {

    private final RampartPaper plugin;
    private final Jedis jedis;
    private final String serverName;
    private final String serverDomain;
    private final String serverIp;
    private final int serverPort;
    private BukkitRunnable task;

    public ShieldAgent(RampartPaper plugin) {
        this.plugin = plugin;

        String redisUrl = System.getenv("RAMPART_REDIS_URL");
        if (redisUrl == null || redisUrl.isEmpty()) {
            redisUrl = "redis://127.0.0.1:6379/0";
        }

        this.jedis = new Jedis(URI.create(redisUrl));

        String name = System.getenv("RAMPART_SERVER_NAME");
        if (name == null || name.isEmpty()) {
            int rand = ThreadLocalRandom.current().nextInt(0x10000);
            name = "paper-" + String.format("%04x", rand);
        }
        this.serverName = name;

        String domain = System.getenv("RAMPART_SERVER_DOMAIN");
        this.serverDomain = (domain == null) ? "" : domain;

        String ip = System.getenv("RAMPART_SERVER_IP");
        if (ip == null || ip.isEmpty()) {
            try {
                ip = InetAddress.getLocalHost().getHostAddress();
            } catch (UnknownHostException e) {
                ip = "127.0.0.1";
            }
        }
        this.serverIp = ip;

        this.serverPort = plugin.getServer().getPort();
    }

    public void start() {
        register();

        task = new BukkitRunnable() {
            @Override
            public void run() {
                heartbeat();
            }
        };
        task.runTaskTimer(plugin, 0L, 20L);
    }

    public void shutdown() {
        if (task != null) {
            task.cancel();
        }
        try {
            setOffline();
        } finally {
            jedis.close();
        }
    }

    private void register() {
        try {
            String json = buildJson("online", plugin.getServer().getOnlinePlayers().size(),
                plugin.getServer().getMaxPlayers(), Bukkit.getTPS()[0]);
            jedis.set("rampart:servers:" + serverName, json);
            plugin.getLogger().info("Registered server " + serverName + " in Redis at " + serverIp + ":" + serverPort);
        } catch (Exception e) {
            plugin.getLogger().severe("Failed to register in Redis: " + e.getMessage());
        }
    }

    private void heartbeat() {
        try {
            int online = plugin.getServer().getOnlinePlayers().size();
            int maxPlayers = plugin.getServer().getMaxPlayers();
            double tps = Bukkit.getTPS()[0];
            String json = buildJson("online", online, maxPlayers, tps);
            jedis.set("rampart:servers:" + serverName, json);
        } catch (Exception e) {
            plugin.getLogger().severe("Heartbeat error: " + e.getMessage());
        }
    }

    private void setOffline() {
        try {
            int online = plugin.getServer().getOnlinePlayers().size();
            int maxPlayers = plugin.getServer().getMaxPlayers();
            double tps = Bukkit.getTPS()[0];
            String json = buildJson("offline", online, maxPlayers, tps);
            jedis.set("rampart:servers:" + serverName, json);
            plugin.getLogger().info("Server " + serverName + " marked offline in Redis");
        } catch (Exception e) {
            plugin.getLogger().severe("Failed to mark offline in Redis: " + e.getMessage());
        }
    }

    private String buildJson(String status, int online, int maxPlayers, double tps) {
        return "{\"name\":\"" + serverName + "\",\"type\":\"paper\",\"domain\":\"" + serverDomain
            + "\",\"ip\":\"" + serverIp
            + "\",\"port\":" + serverPort + ",\"status\":\"" + status
            + "\",\"online\":" + online + ",\"max_players\":" + maxPlayers
            + ",\"tps\":" + tps
            + ",\"last_heartbeat\":" + System.currentTimeMillis() / 1000 + "}";
    }
}
