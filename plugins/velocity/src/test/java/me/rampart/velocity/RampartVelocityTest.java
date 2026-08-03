package me.rampart.velocity;

import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class RampartVelocityTest {

    @Test
    void hmacProduces64HexChars() {
        String sig = hmacHex("play.example.com", "test_secret");
        assertNotNull(sig);
        assertEquals(64, sig.length());
        assertTrue(sig.matches("[0-9a-f]{64}"));
    }

    @Test
    void hmacSameInputSameOutput() {
        String a = hmacHex("play.example.com", "secret");
        String b = hmacHex("play.example.com", "secret");
        assertEquals(a, b);
    }

    @Test
    void hmacDifferentSecretDifferentOutput() {
        String a = hmacHex("play.example.com", "secret1");
        String b = hmacHex("play.example.com", "secret2");
        assertNotEquals(a, b);
    }

    @Test
    void hmacDifferentInputDifferentOutput() {
        String a = hmacHex("play.example.com", "secret");
        String b = hmacHex("hub.example.com", "secret");
        assertNotEquals(a, b);
    }

    @Test
    void constantTimeEqualsSame() {
        assertTrue(constantTimeEquals("abcdef", "abcdef"));
    }

    @Test
    void constantTimeEqualsDifferent() {
        assertFalse(constantTimeEquals("abcdef", "abcdeg"));
    }

    @Test
    void constantTimeEqualsDifferentLength() {
        assertFalse(constantTimeEquals("abc", "abcd"));
    }

    @Test
    void constantTimeEqualsEmpty() {
        assertTrue(constantTimeEquals("", ""));
    }

    @Test
    void constantTimeEqualsNullSafety() {
        assertFalse(constantTimeEquals(null, "a"));
        assertFalse(constantTimeEquals("a", null));
    }

    @Test
    void domainCheckRejectsIpv4() {
        assertTrue(DomainCheckUtil.isIpAddress("192.168.1.1"));
        assertTrue(DomainCheckUtil.isIpAddress("0.0.0.0"));
        assertTrue(DomainCheckUtil.isIpAddress("255.255.255.255"));
    }

    @Test
    void domainCheckAllowsDomains() {
        assertTrue(DomainCheckUtil.isDomainAllowed("play.example.com", List.of("example.com")));
        assertTrue(DomainCheckUtil.isDomainAllowed("mc.example.com", List.of("example.com")));
        assertFalse(DomainCheckUtil.isIpAddress("play.example.com"));
        assertFalse(DomainCheckUtil.isIpAddress("localhost"));
    }

    @Test
    void domainCheckRejectsInvalidIp() {
        assertFalse(DomainCheckUtil.isIpAddress("256.1.2.3"));
        assertFalse(DomainCheckUtil.isIpAddress("1.2.3.4.5"));
        assertFalse(DomainCheckUtil.isIpAddress("abc.def.ghi.jkl"));
        assertFalse(DomainCheckUtil.isIpAddress(""));
        assertFalse(DomainCheckUtil.isIpAddress(null));
    }

    @Test
    void domainCheckSubdomainMatch() {
        assertTrue(DomainCheckUtil.isDomainAllowed("play.example.com", List.of("example.com")));
        assertTrue(DomainCheckUtil.isDomainAllowed("survival.hub.example.com", List.of("example.com")));
    }

    @Test
    void domainCheckExactMatch() {
        assertTrue(DomainCheckUtil.isDomainAllowed("example.com", List.of("example.com")));
    }

    @Test
    void domainCheckNoMatch() {
        assertFalse(DomainCheckUtil.isDomainAllowed("evil.com", List.of("example.com")));
    }

    @Test
    void domainCheckEmptyWhitelistAllowsAll() {
        assertTrue(DomainCheckUtil.isDomainAllowed("anything.com", List.of()));
        assertTrue(DomainCheckUtil.isDomainAllowed("192.168.1.1", List.of()));
    }

    // --- Dual-key hostname verification (mirrors HmacCheckListener.verifyHostname) ---

    @Test
    void hostnameVerifyAcceptsValidSignature() {
        long ts = System.currentTimeMillis() / 1000;
        String raw = signHostname("play.example.com", ts, 3600, "test_secret");
        assertTrue(HmacCheckListener.verifyHostname(raw, "test_secret".getBytes(), 3600, 60));
    }

    @Test
    void hostnameVerifyRejectsWrongSecret() {
        long ts = System.currentTimeMillis() / 1000;
        String raw = signHostname("play.example.com", ts, 3600, "secret_a");
        assertFalse(HmacCheckListener.verifyHostname(raw, "secret_b".getBytes(), 3600, 60));
    }

    @Test
    void hostnameVerifyRejectsTamperedSig() {
        long ts = System.currentTimeMillis() / 1000;
        String raw = signHostname("play.example.com", ts, 3600, "test_secret");
        char flip = raw.charAt(raw.length() - 1) == '0' ? '1' : '0';
        String tampered = raw.substring(0, raw.length() - 1) + flip;
        assertFalse(HmacCheckListener.verifyHostname(tampered, "test_secret".getBytes(), 3600, 60));
    }

    @Test
    void hostnameVerifyRejectsUnsigned() {
        assertFalse(HmacCheckListener.verifyHostname("play.example.com", "test_secret".getBytes(), 3600, 60));
    }

    @Test
    void hostnameVerifyRejectsMalformedTs() {
        String raw = "play.example.com\0shield\0notanumber\0" + "a".repeat(64);
        assertFalse(HmacCheckListener.verifyHostname(raw, "test_secret".getBytes(), 3600, 60));
    }

    @Test
    void hostnameVerifyRejectsBadSigLength() {
        long ts = System.currentTimeMillis() / 1000;
        String raw = "play.example.com\0shield\0" + ts + "\0" + "a".repeat(63);
        assertFalse(HmacCheckListener.verifyHostname(raw, "test_secret".getBytes(), 3600, 60));
    }

    @Test
    void hostnameVerifyRejectsExpired() {
        long ts = System.currentTimeMillis() / 1000 - 120;
        String raw = signHostname("play.example.com", ts, 3600, "test_secret");
        assertFalse(HmacCheckListener.verifyHostname(raw, "test_secret".getBytes(), 3600, 60));
    }

    @Test
    void hostnameVerifyRejectsFutureTimestamp() {
        long ts = System.currentTimeMillis() / 1000 + 3600;
        String raw = signHostname("play.example.com", ts, 3600, "test_secret");
        assertFalse(HmacCheckListener.verifyHostname(raw, "test_secret".getBytes(), 3600, 60));
    }

    @Test
    void hostnameVerifyAcceptsPreviousRotationBucket() {
        long ts = System.currentTimeMillis() / 1000;
        long bucket = ts / 3600 - 1;
        String raw = "play.example.com\0shield\0" + ts + "\0"
            + sign("play.example.com", ts, bucket, "test_secret");
        assertTrue(HmacCheckListener.verifyHostname(raw, "test_secret".getBytes(), 3600, 60));
    }

    private static String signHostname(String domain, long ts, long rotationSecs, String secret) {
        long bucket = ts / rotationSecs;
        return domain + "\0shield\0" + ts + "\0" + sign(domain, ts, bucket, secret);
    }

    private static String sign(String domain, long ts, long bucket, String secret) {
        byte[] derived = hmacRaw(secret.getBytes(), ("rampart-key-" + bucket).getBytes());
        byte[] sig = hmacRaw(derived, (domain + "|" + ts).getBytes());
        return toHex(sig);
    }

    private static byte[] hmacRaw(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new AssertionError(e);
        }
    }

    private static String toHex(byte[] raw) {
        StringBuilder sb = new StringBuilder(raw.length * 2);
        for (byte b : raw) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }

    // --- HMAC utility (mirrors HmacCheckListener) ---

    private String hmacHex(String data, String secret) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(), "HmacSHA256"));
            byte[] raw = mac.doFinal(data.getBytes());
            StringBuilder sb = new StringBuilder(raw.length * 2);
            for (byte b : raw) {
                sb.append(String.format("%02x", b & 0xFF));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            return null;
        }
    }

    // --- constant-time equals (mirrors HmacCheckListener) ---

    private boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        if (a.length() != b.length()) return false;
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }
}
