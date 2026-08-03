package me.rampart.paper;

import net.kyori.adventure.text.Component;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerLoginEvent;

public class HmacLoginListener implements Listener {

    private final RampartPaper plugin;

    public HmacLoginListener(RampartPaper plugin) {
        this.plugin = plugin;
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onPlayerLogin(PlayerLoginEvent event) {
        String secretEnv = System.getenv("RAMPART_HMAC_SECRET");
        if (secretEnv == null || secretEnv.isEmpty()) return;

        String raw = event.getHostname();
        if (raw == null || raw.isEmpty()) return;

        if (!plugin.verifyHostname(raw)) {
            plugin.getLogger().warning("HMAC verification failed for " + event.getAddress());
            event.disallow(PlayerLoginEvent.Result.KICK_OTHER,
                Component.text("Connection rejected: invalid signature"));
        }
    }
}
