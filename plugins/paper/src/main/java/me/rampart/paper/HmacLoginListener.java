package me.rampart.paper;

import net.kyori.adventure.text.Component;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerLoginEvent;

public class HmacLoginListener implements Listener {

    private static final int HEX_SIG_LENGTH = 64;

    private final RampartPaper plugin;

    public HmacLoginListener(RampartPaper plugin) {
        this.plugin = plugin;
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onPlayerLogin(PlayerLoginEvent event) {
        String secretEnv = System.getenv("RAMPART_HMAC_SECRET");
        if (secretEnv == null || secretEnv.isEmpty()) return;

        byte[] secret = secretEnv.getBytes();
        String raw = event.getHostname();
        if (raw == null || raw.isEmpty()) return;

        int sepIdx = raw.indexOf(RampartPaper.SHIELD_SEPARATOR);
        if (sepIdx < 0) {
            return;
        }

        String domain = raw.substring(0, sepIdx);
        String sig = raw.substring(sepIdx + RampartPaper.SHIELD_SEPARATOR.length());

        if (sig.length() != HEX_SIG_LENGTH) {
            plugin.getLogger().warning("Invalid sig length from " + event.getAddress() +
                ": got " + sig.length() + ", expected " + HEX_SIG_LENGTH);
            event.disallow(PlayerLoginEvent.Result.KICK_OTHER,
                Component.text("Connection rejected: invalid signature"));
            return;
        }

        String expected = plugin.hmacHex(domain, secret);
        if (expected == null || !plugin.constantTimeEquals(sig, expected)) {
            plugin.getLogger().warning("HMAC verification failed for " + event.getAddress());
            event.disallow(PlayerLoginEvent.Result.KICK_OTHER,
                Component.text("Connection rejected: invalid signature"));
        }
    }
}
