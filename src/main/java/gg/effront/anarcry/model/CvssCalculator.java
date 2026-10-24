package gg.effront.anarcry.model;

public class CvssCalculator {

    // Calcula CVSS v3.1 Base Score a partir de um vector string.
    // Ex: "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N" → 10.0
    // Retorna -1.0 se o vector for inválido.
    public static double calculate(String vector) {
        if (vector == null || vector.isBlank()) {
            return -1.0;
        }

        String v = vector;
        if (v.startsWith("CVSS:3.1/")) {
            v = v.substring("CVSS:3.1/".length());
        }

        String[] parts = v.split("/");
        if (parts.length < 8) {
            return -1.0;
        }

        java.util.Map<String, String> m = new java.util.HashMap<>();
        for (String part : parts) {
            String[] kv = part.split(":");
            if (kv.length != 2) {
                return -1.0;
            }
            m.put(kv[0], kv[1]);
        }

        try {
            double av = parseAV(m.get("AV"));
            double ac = parseAC(m.get("AC"));
            String sVal = m.get("S");
            boolean scopeChanged = "C".equals(sVal);
            double pr = parsePR(m.get("PR"), scopeChanged);
            double ui = parseUI(m.get("UI"));
            double c = parseCIA(m.get("C"));
            double i = parseCIA(m.get("I"));
            double a = parseCIA(m.get("A"));

            if (av < 0 || ac < 0 || pr < 0 || ui < 0 || c < 0 || i < 0 || a < 0) {
                return -1.0;
            }

            double iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a);
            double exploitability = 8.22 * av * ac * pr * ui;

            double impact;
            double base;
            if (!scopeChanged) {
                impact = 6.42 * iss;
                if (impact <= 0) {
                    return 0.0;
                }
                base = Math.min(impact + exploitability, 10.0);
            } else {
                impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
                if (impact <= 0) {
                    return 0.0;
                }
                base = Math.min(1.08 * (impact + exploitability), 10.0);
            }

            return Math.ceil(base * 10.0) / 10.0;

        } catch (Exception e) {
            return -1.0;
        }
    }

    private static double parseAV(String v) {
        if (v == null) {
            return -1.0;
        }
        return switch (v) {
            case "N" -> 0.85;
            case "A" -> 0.62;
            case "L" -> 0.55;
            case "P" -> 0.2;
            default -> -1.0;
        };
    }

    private static double parseAC(String v) {
        if (v == null) {
            return -1.0;
        }
        return switch (v) {
            case "L" -> 0.77;
            case "H" -> 0.44;
            default -> -1.0;
        };
    }

    private static double parsePR(String v, boolean scopeChanged) {
        if (v == null) {
            return -1.0;
        }
        return switch (v) {
            case "N" -> 0.85;
            case "L" -> scopeChanged ? 0.50 : 0.62;
            case "H" -> scopeChanged ? 0.08 : 0.27;
            default -> -1.0;
        };
    }

    private static double parseUI(String v) {
        if (v == null) {
            return -1.0;
        }
        return switch (v) {
            case "N" -> 0.85;
            case "R" -> 0.62;
            default -> -1.0;
        };
    }

    private static double parseCIA(String v) {
        if (v == null) {
            return -1.0;
        }
        return switch (v) {
            case "N" -> 0.0;
            case "L" -> 0.22;
            case "H" -> 0.56;
            default -> -1.0;
        };
    }

    // Converte severity para um vector CVSS padrão por severidade
    public static String defaultVector(Severity severity) {
        return switch (severity) {
            case CRITICAL -> "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N";
            case HIGH -> "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N";
            case MEDIUM -> "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N";
            case LOW -> "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N";
            case INFO -> "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N";
        };
    }
}
