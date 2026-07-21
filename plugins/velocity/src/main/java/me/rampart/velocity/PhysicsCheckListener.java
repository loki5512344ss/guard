package me.rampart.velocity;

import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.DisconnectEvent;
import com.velocitypowered.api.event.connection.LoginEvent;
import com.velocitypowered.api.event.player.PlayerChatEvent;
import com.velocitypowered.api.event.player.PlayerResourcePackStatusEvent;
import com.velocitypowered.api.event.player.PlayerSettingsChangedEvent;
import com.velocitypowered.api.event.player.TabCompleteEvent;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import net.kyori.adventure.text.Component;
import org.slf4j.Logger;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

public class PhysicsCheckListener {

    private static final double[] EXPECTED_Y = new double[128];
    private static final int FALL_THRESHOLD = 3;
    private static final int PROTOCOL_THRESHOLD = 3;
    private static final int VEHICLE_THRESHOLD = 2;
    private static final int PROTOCOL_HISTORY = 5;
    private static final double MAX_BOAT_SPEED = 0.6;
    private static final double MAX_MINECART_SPEED = 0.4;

    static {
        for (int t = 0; t < 128; t++) {
            EXPECTED_Y[t] = 3.92 * (Math.pow(0.98, t) - 1);
        }
    }

    private static final Map<UUID, PlayerTracker> tracked = new ConcurrentHashMap<>();

    private final Logger logger;
    private final ProxyServer server;

    public PhysicsCheckListener(Logger logger, ProxyServer server) {
        this.logger = logger;
        this.server = server;
        server.getScheduler().buildTask(this, this::tickAll)
            .repeat(50, TimeUnit.MILLISECONDS)
            .schedule();
    }

    public static void clearSuspicion(UUID uuid) {
        PlayerTracker tracker = tracked.get(uuid);
        if (tracker != null) {
            tracker.suspicionScore = 0;
            tracker.consecutiveFallViolations = 0;
            tracker.protocolViolations = 0;
            tracker.reVerificationTriggered = false;
        }
    }

    @Subscribe
    public void onLogin(LoginEvent event) {
        Player player = event.getPlayer();
        tracked.put(player.getUniqueId(), new PlayerTracker());
    }

    @Subscribe
    public void onDisconnect(DisconnectEvent event) {
        tracked.remove(event.getPlayer().getUniqueId());
    }

    @Subscribe
    public void onPlayerSettings(PlayerSettingsChangedEvent event) {
        PlayerTracker tracker = tracked.get(event.getPlayer().getUniqueId());
        if (tracker == null) return;
        tracker.virtualTick++;
        tracker.lastEventTime = System.currentTimeMillis();
        tracker.addProtocol("Settings");
    }

    @Subscribe
    public void onPlayerChat(PlayerChatEvent event) {
        PlayerTracker tracker = tracked.get(event.getPlayer().getUniqueId());
        if (tracker == null) return;
        tracker.virtualTick++;
        tracker.lastEventTime = System.currentTimeMillis();
        tracker.addProtocol("Chat");
    }

    @Subscribe
    public void onTabComplete(TabCompleteEvent event) {
        PlayerTracker tracker = tracked.get(event.getPlayer().getUniqueId());
        if (tracker == null) return;
        tracker.addProtocol("TabComplete");
    }

    @Subscribe
    public void onResourcePackStatus(PlayerResourcePackStatusEvent event) {
        PlayerTracker tracker = tracked.get(event.getPlayer().getUniqueId());
        if (tracker == null) return;
        tracker.addProtocol("ResourcePack");
    }

    private void tickAll() {
        for (Map.Entry<UUID, PlayerTracker> entry : tracked.entrySet()) {
            Player player = server.getPlayer(entry.getKey()).orElse(null);
            if (player == null) continue;
            PlayerTracker tracker = entry.getValue();
            checkFalling(player, tracker);
            checkProtocol(player, tracker);
        }
    }

    private void checkFalling(Player player, PlayerTracker tracker) {
        if (player.hasPermission("rampart.bypass.fly")) return;
        if (tracker.virtualTick >= 128) return;
        if (tracker.virtualTick < 0) return;

        double expectedDelta = EXPECTED_Y[tracker.virtualTick];
        double actualDelta = 0;
        if (tracker.lastEventTime > 0) {
            long dt = System.currentTimeMillis() - tracker.lastEventTime;
            actualDelta = 3.92 * (Math.pow(0.98, Math.max(1, dt / 50.0)) - 1);
        }
        if (Math.abs(actualDelta - expectedDelta) > 0.001) {
            tracker.consecutiveFallViolations++;
            if (tracker.consecutiveFallViolations >= FALL_THRESHOLD) {
                tracker.suspicionScore += FALL_THRESHOLD;
                tracker.consecutiveFallViolations = 0;
                logger.warn("Falling check triggered for {} (score={})",
                    player.getUsername(), tracker.suspicionScore);
                if (tracker.suspicionScore >= FALL_THRESHOLD) {
                    triggerReVerify(player, tracker);
                }
            }
        } else {
            tracker.consecutiveFallViolations = 0;
        }
    }

    private void checkProtocol(Player player, PlayerTracker tracker) {
        if (tracker.protocolHistory.size() < PROTOCOL_HISTORY) return;
        boolean unexpected = false;
        String last = tracker.protocolHistory.getLast();
        if (last.equals("Chat") || last.equals("TabComplete")) {
        } else {
            unexpected = true;
            tracker.protocolViolations++;
            if (tracker.protocolViolations >= PROTOCOL_THRESHOLD) {
                tracker.suspicionScore += PROTOCOL_THRESHOLD;
                tracker.protocolViolations = 0;
                logger.warn("Protocol check triggered for {} (score={})",
                    player.getUsername(), tracker.suspicionScore);
                if (tracker.suspicionScore >= PROTOCOL_THRESHOLD) {
                    triggerReVerify(player, tracker);
                }
            }
        }
    }

    private void triggerReVerify(Player player, PlayerTracker tracker) {
        if (tracker.reVerificationTriggered) return;
        tracker.reVerificationTriggered = true;
        player.disconnect(Component.text("Re-verification required. Please reconnect."));
        logger.info("Triggered re-verification for {}", player.getUsername());
    }

    private static class PlayerTracker {
        int virtualTick = 0;
        long lastEventTime = 0;
        int consecutiveFallViolations = 0;
        int protocolViolations = 0;
        int suspicionScore = 0;
        boolean reVerificationTriggered = false;
        Deque<String> protocolHistory = new ArrayDeque<>();

        void addProtocol(String type) {
            protocolHistory.addLast(type);
            if (protocolHistory.size() > PROTOCOL_HISTORY) {
                protocolHistory.removeFirst();
            }
        }
    }
}
