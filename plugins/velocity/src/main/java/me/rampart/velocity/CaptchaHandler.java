package me.rampart.velocity;

import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.command.CommandExecuteEvent;
import com.velocitypowered.api.event.connection.DisconnectEvent;
import com.velocitypowered.api.event.player.PlayerChatEvent;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import net.kyori.adventure.text.Component;
import org.slf4j.Logger;

import java.util.Map;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class CaptchaHandler {

    private static final int MAX_ATTEMPTS = 3;
    private static final long EXPIRY_MS = 30_000;

    private final Logger logger;
    private final ProxyServer server;
    private final Map<UUID, CaptchaSession> pending = new ConcurrentHashMap<>();
    private final Random random = new Random();

    public CaptchaHandler(Logger logger, ProxyServer server) {
        this.logger = logger;
        this.server = server;
    }

    public void challenge(Player player) {
        int token = 1000 + random.nextInt(9000);
        pending.put(player.getUniqueId(), new CaptchaSession(token, 0, System.currentTimeMillis() + EXPIRY_MS));
        player.sendMessage(Component.text("§e[Rampart] Please type §6/verify " + token + " §eto verify you are not a bot."));
        logger.info("CAPTCHA challenge sent to {}", player.getUsername());
    }

    @Subscribe
    public void onPlayerChat(PlayerChatEvent event) {
        Player player = event.getPlayer();
        CaptchaSession session = pending.get(player.getUniqueId());
        if (session == null) return;

        if (System.currentTimeMillis() > session.expiry) {
            pending.remove(player.getUniqueId());
            player.disconnect(Component.text("CAPTCHA timed out"));
            logger.info("CAPTCHA timed out for {}", player.getUsername());
            return;
        }

        String message = event.getMessage().trim();
        if (message.startsWith("/verify ")) {
            event.setResult(PlayerChatEvent.ChatResult.denied());
            String[] parts = message.split(" ");
            if (parts.length == 2) {
                try {
                    int guess = Integer.parseInt(parts[1]);
                    if (guess == session.token) {
                        pending.remove(player.getUniqueId());
                        player.sendMessage(Component.text("§a[Rampart] You have been verified."));
                        logger.info("CAPTCHA passed for {}", player.getUsername());
                        HmacCheckListener.markVerified(player.getUniqueId());
                        PhysicsCheckListener.clearSuspicion(player.getUniqueId());
                        return;
                    }
                } catch (NumberFormatException ignored) {
                }
            }
            session.attempts++;
            if (session.attempts >= MAX_ATTEMPTS) {
                pending.remove(player.getUniqueId());
                player.disconnect(Component.text("CAPTCHA failed"));
                logger.warn("CAPTCHA failed for {}", player.getUsername());
            } else {
                player.sendMessage(Component.text("§c[Rampart] Incorrect. Attempts remaining: " + (MAX_ATTEMPTS - session.attempts)));
            }
        }
    }

    @Subscribe
    public void onCommand(CommandExecuteEvent event) {
        if (!(event.getCommandSource() instanceof Player player)) return;
        CaptchaSession session = pending.get(player.getUniqueId());
        if (session == null) return;
        String cmd = event.getCommand();
        if (!cmd.startsWith("verify ")) {
            event.setResult(CommandExecuteEvent.CommandResult.denied());
            player.sendMessage(Component.text("§c[Rampart] You must complete the CAPTCHA first. Type /verify <number>"));
        }
    }

    @Subscribe
    public void onDisconnect(DisconnectEvent event) {
        pending.remove(event.getPlayer().getUniqueId());
    }

    private static class CaptchaSession {
        final int token;
        int attempts;
        final long expiry;

        CaptchaSession(int token, int attempts, long expiry) {
            this.token = token;
            this.attempts = attempts;
            this.expiry = expiry;
        }
    }
}
