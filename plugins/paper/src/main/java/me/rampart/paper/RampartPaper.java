package me.rampart.paper;

import org.bukkit.plugin.java.JavaPlugin;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

public class RampartPaper extends JavaPlugin {

    static final String SHIELD_SEPARATOR = "\0shield\0";
    static final String HMAC_ALGO = "HmacSHA256";
    static final int HEX_SIG_LENGTH = 64;

    private ShieldAgent shieldAgent;
    private long rotationSecs = 3600;
    private long ttlSecs = 60;

    @Override
    public void onEnable() {
        rotationSecs = envLong("RAMPART_HMAC_ROTATION_SECS", 3600);
        ttlSecs = envLong("RAMPART_HMAC_TTL_SECS", 60);

        String secret = System.getenv("RAMPART_HMAC_SECRET");
        if (secret == null || secret.isEmpty()) {
            getLogger().warning("RAMPART_HMAC_SECRET not set — HMAC verification disabled");
        } else {
            getLogger().info("Rampart HMAC verification enabled");
        }
        getServer().getPluginManager().registerEvents(new HmacLoginListener(this), this);

        try {
            shieldAgent = new ShieldAgent(this);
            shieldAgent.start();
            getLogger().info("ShieldAgent started");
        } catch (Exception e) {
            getLogger().severe("Failed to start ShieldAgent: " + e.getMessage());
        }
    }

    @Override
    public void onDisable() {
        if (shieldAgent != null) {
            shieldAgent.shutdown();
            getLogger().info("ShieldAgent shut down");
        }
    }

    boolean verifyHostname(String raw) {
        String secretEnv = System.getenv("RAMPART_HMAC_SECRET");
        if (secretEnv == null || secretEnv.isEmpty()) return false;
        return verifyHostname(raw, secretEnv.getBytes(StandardCharsets.UTF_8), rotationSecs, ttlSecs);
    }

    private boolean verifyHostname(String raw, byte[] secret, long rotation, long ttl) {
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
        if (now < ts || now - ts > ttl) return false;

        long tsBucket = ts / rotation;
        for (long bucket : new long[]{tsBucket, tsBucket - 1}) {
            byte[] derivedKey = hmacBytes(secret, ("rampart-key-" + bucket).getBytes(StandardCharsets.UTF_8));
            if (derivedKey == null) continue;
            String expected = toHex(hmacBytes(derivedKey, (domain + "|" + ts).getBytes(StandardCharsets.UTF_8)));
            if (expected != null && constantTimeEquals(sig, expected)) {
                return true;
            }
        }
        return false;
    }

    private byte[] hmacBytes(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGO);
            mac.init(new SecretKeySpec(key, HMAC_ALGO));
            return mac.doFinal(data);
        } catch (Exception e) {
            getLogger().severe("HMAC error: " + e.getMessage());
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

    boolean constantTimeEquals(String a, String b) {
        if (a.length() != b.length()) return false;
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }

    private static long envLong(String name, long def) {
        String value = System.getenv(name);
        if (value == null || value.isEmpty()) return def;
        try {
            return Long.parseLong(value.trim());
        } catch (NumberFormatException e) {
            return def;
        }
    }
}
