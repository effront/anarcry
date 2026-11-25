package gg.effront.anarcry.fuzzer;

import java.util.List;

public enum AttackType {

    SNIPER("Sniper", "One payload list, iterates through each position one at a time"), BATTERING_RAM("Battering Ram",
            "Same payload inserted into all positions simultaneously"), PITCHFORK("Pitchfork",
                    "Separate list per position, stepped in parallel"), CLUSTER_BOMB("Cluster Bomb",
                            "Separate list per position, full cartesian product");

    private final String label;
    private final String description;

    AttackType(String label, String description) {
        this.label = label;
        this.description = description;
    }

    public String label() {
        return label;
    }

    public String description() {
        return description;
    }

    public long estimateRequests(int positionCount, List<? extends PayloadSource> sources) {
        if (sources.isEmpty() || positionCount == 0) {
            return 0;
        }
        return switch (this) {
            case SNIPER -> (long) positionCount * sources.getFirst().size();
            case BATTERING_RAM -> sources.getFirst().size();
            case PITCHFORK -> sources.stream().mapToLong(PayloadSource::size).min().orElse(0);
            case CLUSTER_BOMB -> {
                long product = 1;
                for (PayloadSource src : sources) {
                    product *= src.size();
                    if (product > 10_000_000) {
                        yield product;
                    }
                }
                yield product;
            }
        };
    }

    @Override
    public String toString() {
        return label;
    }
}
