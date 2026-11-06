package gg.effront.anarcry.apiclient.vars;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

public final class BuiltInFunctions {

    private static final String ALPHANUM = "abcdefghijklmnopqrstuvwxyz0123456789";

    private BuiltInFunctions() {
    }

    public static String resolve(String key) {
        return switch (key) {
            case "timestamp" -> String.valueOf(Instant.now().getEpochSecond());
            case "isoTimestamp" -> DateTimeFormatter.ISO_INSTANT.format(Instant.now().atOffset(ZoneOffset.UTC));
            case "randomInt" -> String.valueOf(ThreadLocalRandom.current().nextInt(10_000));
            case "randomFloat" -> String.format("%.4f", ThreadLocalRandom.current().nextDouble());
            case "guid", "uuid" -> UUID.randomUUID().toString();
            case "randomEmail" -> "user_" + randomAlphaNum(8) + "@test.com";
            case "randomString" -> randomAlphaNum(10);
            case "randomBoolean" -> String.valueOf(ThreadLocalRandom.current().nextBoolean());
            case "randomColor" -> String.format("#%06x", ThreadLocalRandom.current().nextInt(0x1000000));
            case "randomIP" -> randomIp();
            default -> null;
        };
    }

    private static String randomAlphaNum(int len) {
        ThreadLocalRandom rng = ThreadLocalRandom.current();
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            sb.append(ALPHANUM.charAt(rng.nextInt(ALPHANUM.length())));
        }
        return sb.toString();
    }

    private static String randomIp() {
        ThreadLocalRandom rng = ThreadLocalRandom.current();
        return rng.nextInt(1, 256) + "." + rng.nextInt(256) + "." + rng.nextInt(256) + "." + rng.nextInt(1, 256);
    }
}
