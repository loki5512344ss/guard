package me.rampart.velocity;

import java.util.List;

public class DomainCheckUtil {

    public static boolean isIpAddress(String hostname) {
        if (hostname == null || hostname.isEmpty()) return false;

        if (hostname.chars().allMatch(c -> c == '.' || Character.isDigit(c))) {
            String[] parts = hostname.split("\\.");
            if (parts.length == 4) {
                try {
                    for (String p : parts) {
                        int val = Integer.parseInt(p);
                        if (val < 0 || val > 255) return false;
                    }
                    return true;
                } catch (NumberFormatException e) {
                    return false;
                }
            }
        }
        return false;
    }

    public static boolean isDomainAllowed(String hostname, List<String> allowedDomains) {
        if (allowedDomains == null || allowedDomains.isEmpty()) return true;
        String clean = hostname.split("\0")[0];
        return allowedDomains.stream()
            .anyMatch(d -> clean.equals(d) || clean.endsWith("." + d));
    }
}
