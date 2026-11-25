package gg.effront.anarcry.fuzzer;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public record FuzzPosition(int index, int start, int end) {

    private static final Pattern MARKER = Pattern.compile("\\{\\{(\\d+)\\}\\}");

    public static List<FuzzPosition> parse(String template) {
        List<FuzzPosition> positions = new ArrayList<>();
        Matcher m = MARKER.matcher(template);
        while (m.find()) {
            int idx = Integer.parseInt(m.group(1));
            positions.add(new FuzzPosition(idx, m.start(), m.end()));
        }
        return positions;
    }

    public static String inject(String template, List<FuzzPosition> positions, String[] payloads) {
        StringBuilder sb = new StringBuilder(template);
        for (int i = positions.size() - 1; i >= 0; i--) {
            FuzzPosition pos = positions.get(i);
            int pIdx = pos.index() - 1;
            String payload = pIdx >= 0 && pIdx < payloads.length ? payloads[pIdx] : "";
            sb.replace(pos.start(), pos.end(), payload);
        }
        return sb.toString();
    }

    public static int maxIndex(List<FuzzPosition> positions) {
        return positions.stream().mapToInt(FuzzPosition::index).max().orElse(0);
    }
}
