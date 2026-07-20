package me.rampart.velocity;

import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.LoginEvent;
import net.kyori.adventure.text.Component;
import org.slf4j.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class HmacCheckListener {

    private static final String SHIELD_SEPARATOR = "\0shield\0";
    private static final String HMAC_ALGO = "HmacSHA256";
    private static final int HEX_SIG_LENGTH = 64;

    private final Logger logger;
    private final byte[] secret;

    public HmacCheckListener(Logger logger, String secret) {
        this.logger = logger;
        this.secret = secret.getBytes();
    }

    @Subscribe
    public void onLogin(LoginEvent event) {
        var player = event.getPlayer();
        var vh = player.getVirtualHost();
        if (vh.isEmpty()) {
            event.setResult(LoginEvent.ComponentResult.denied(
                Component.text("Connection rejected: no virtual host")
            ));
            return;
        }

        String raw = vh.get().getHostString();
        if (raw == null || raw.isEmpty()) {
            event.setResult(LoginEvent.ComponentResult.denied(
                Component.text("Connection rejected: empty hostname")
            ));
            return;
        }

        int sepIdx = raw.indexOf(SHIELD_SEPARATOR);
        if (sepIdx < 0) {
            event.setResult(LoginEvent.ComponentResult.denied(
                Component.text("Connection rejected: unsigned connection")
            ));
            return;
        }

        String domain = raw.substring(0, sepIdx);
        String sig = raw.substring(sepIdx + SHIELD_SEPARATOR.length());

        if (sig.length() != HEX_SIG_LENGTH) {
            logger.warn("Invalid HMAC signature length from {}: got {}, expected {}",
                player.getRemoteAddress(), sig.length(), HEX_SIG_LENGTH);
            event.setResult(LoginEvent.ComponentResult.denied(
                Component.text("Connection rejected: invalid signature")
            ));
            return;
        }

        String expected = hmacHex(domain);
        if (expected == null) {
            event.setResult(LoginEvent.ComponentResult.denied(
                Component.text("Connection rejected: internal error")
            ));
            return;
        }

        if (!constantTimeEquals(sig, expected)) {
            logger.warn("HMAC verification failed for {} (domain: {})",
                player.getRemoteAddress(), domain);
            event.setResult(LoginEvent.ComponentResult.denied(
                Component.text("Connection rejected: invalid signature")
            ));
        }
    }

    private String hmacHex(String data) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGO);
            mac.init(new SecretKeySpec(secret, HMAC_ALGO));
            byte[] raw = mac.doFinal(data.getBytes());
            StringBuilder sb = new StringBuilder(raw.length * 2);
            for (byte b : raw) {
                sb.append(String.format("%02x", b & 0xFF));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            logger.error("HMAC error", e);
            return null;
        }
    }

    private boolean constantTimeEquals(String a, String b) {
        if (a.length() != b.length()) return false;
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }
}
