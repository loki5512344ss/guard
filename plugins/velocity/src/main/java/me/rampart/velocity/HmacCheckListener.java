package me.rampart.velocity;

import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.LoginEvent;
import net.kyori.adventure.text.Component;
import org.slf4j.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class HmacCheckListener {

    private static final String SHIELD_SEPARATOR = "\0shield\0";
    private static final String HMAC_ALGO = "HmacSHA256";
    private static final int HEX_SIG_LENGTH = 64;

    private static final Map<UUID, Boolean> verifiedPlayers = new ConcurrentHashMap<>();

    private final Logger logger;
    private final byte[] secret;
    private final long rotationSecs;
    private final long ttlSecs;

    public HmacCheckListener(Logger logger, String secret, long rotationSecs, long ttlSecs) {
        this.logger = logger;
        this.secret = secret.getBytes(StandardCharsets.UTF_8);
        this.rotationSecs = rotationSecs;
        this.ttlSecs = ttlSecs;
    }

    public static void markVerified(UUID uuid) {
        verifiedPlayers.put(uuid, true);
        PhysicsCheckListener.clearSuspicion(uuid);
    }

    public static boolean isVerified(UUID uuid) {
        return verifiedPlayers.containsKey(uuid);
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

        if (raw.indexOf(SHIELD_SEPARATOR) < 0) {
            event.setResult(LoginEvent.ComponentResult.denied(
                Component.text("Connection rejected: unsigned connection")
            ));
            return;
        }

        if (!verifyHostname(raw, secret, rotationSecs, ttlSecs)) {
            logger.warn("HMAC verification failed for {} (hostname: {})",
                player.getRemoteAddress(), raw);
            event.setResult(LoginEvent.ComponentResult.denied(
                Component.text("Connection rejected: invalid signature")
            ));
        }
    }

    static boolean verifyHostname(String raw, byte[] secret, long rotationSecs, long ttlSecs) {
        if (raw == null) return false;
        int sepIdx = raw.indexOf(SHIELD_SEPARATOR);
        if (sepIdx < 0) return false;

        String domain = raw.substring(0, sepIdx);
        String rest = raw.substring(sepIdx + SHIELD_SEPARATOR.length());
        int tsSep = rest.indexOf('\0');
        if (tsSep < 0) return false;
        String tsStr = rest.substring(0, tsSep);
        String sig = rest.substring(tsSep + 1);

        if (sig.length() != HEX_SIG_LENGTH || !sig.matches("[0-9a-f]+")) return false;

        long ts;
        try {
            ts = Long.parseLong(tsStr);
        } catch (NumberFormatException e) {
            return false;
        }

        long now = System.currentTimeMillis() / 1000;
        if (now < ts || now - ts > ttlSecs) return false;

        long tsBucket = ts / rotationSecs;
        for (long bucket : new long[]{tsBucket, tsBucket - 1}) {
            String expected = sign(domain, ts, bucket, secret);
            if (expected != null && constantTimeEquals(sig, expected)) {
                return true;
            }
        }
        return false;
    }

    private static String sign(String domain, long ts, long bucket, byte[] masterSecret) {
        byte[] derivedKey = hmacRaw(masterSecret, ("rampart-key-" + bucket).getBytes(StandardCharsets.UTF_8));
        if (derivedKey == null) return null;
        byte[] sig = hmacRaw(derivedKey, (domain + "|" + ts).getBytes(StandardCharsets.UTF_8));
        if (sig == null) return null;
        return toHex(sig);
    }

    private static byte[] hmacRaw(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGO);
            mac.init(new SecretKeySpec(key, HMAC_ALGO));
            return mac.doFinal(data);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            return null;
        }
    }

    private static String toHex(byte[] raw) {
        StringBuilder sb = new StringBuilder(raw.length * 2);
        for (byte b : raw) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a.length() != b.length()) return false;
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }
}
