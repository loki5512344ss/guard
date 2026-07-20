package me.rampart.paper;

import org.bukkit.plugin.java.JavaPlugin;

public class RampartPaper extends JavaPlugin {

    static final String SHIELD_SEPARATOR = "\0shield\0";

    private ShieldAgent shieldAgent;

    @Override
    public void onEnable() {
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

    String hmacHex(String data, byte[] secret) {
        try {
            var mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(secret, "HmacSHA256"));
            byte[] raw = mac.doFinal(data.getBytes());
            StringBuilder sb = new StringBuilder(raw.length * 2);
            for (byte b : raw) {
                sb.append(String.format("%02x", b & 0xFF));
            }
            return sb.toString();
        } catch (Exception e) {
            getLogger().severe("HMAC error: " + e.getMessage());
            return null;
        }
    }

    boolean constantTimeEquals(String a, String b) {
        if (a.length() != b.length()) return false;
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }
}
