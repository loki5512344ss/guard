package me.rampart.velocity;

import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.LoginEvent;
import net.kyori.adventure.text.Component;
import org.slf4j.Logger;

import java.net.InetSocketAddress;
import java.util.List;

public class DomainCheckListener {

    private final Logger logger;
    private final List<String> allowedDomains;

    public DomainCheckListener(Logger logger, List<String> allowedDomains) {
        this.logger = logger;
        this.allowedDomains = allowedDomains;
    }

    @Subscribe
    public void onLogin(LoginEvent event) {
        if (allowedDomains.isEmpty()) return;

        var player = event.getPlayer();
        String hostname = player.getVirtualHost()
            .map(InetSocketAddress::getHostString)
            .orElse("");

        if (hostname.isEmpty()) {
            event.setResult(LoginEvent.ComponentResult.denied(
                Component.text("Connection rejected: no hostname")
            ));
            return;
        }

        String clean = hostname.split("\0")[0];

        if (DomainCheckUtil.isIpAddress(clean)) {
            logger.warn("Direct IP connect blocked from {} (hostname: {})",
                player.getRemoteAddress(), clean);
            event.setResult(LoginEvent.ComponentResult.denied(
                Component.text("Direct IP connections are not allowed")
            ));
            return;
        }

        if (!DomainCheckUtil.isDomainAllowed(clean, allowedDomains)) {
            logger.warn("Domain not allowed from {} (hostname: {})",
                player.getRemoteAddress(), clean);
            event.setResult(LoginEvent.ComponentResult.denied(
                Component.text("This domain is not allowed")
            ));
        }
    }
}
