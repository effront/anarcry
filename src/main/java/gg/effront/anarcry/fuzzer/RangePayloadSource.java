package gg.effront.anarcry.fuzzer;

import java.util.Iterator;
import java.util.NoSuchElementException;

public final class RangePayloadSource implements PayloadSource {

    private final long from;
    private final long to;
    private final long step;
    private final int padding;

    public RangePayloadSource(long from, long to, long step, int padding) {
        this.from = from;
        this.to = to;
        this.step = step > 0 ? step : 1;
        this.padding = padding;
    }

    @Override
    public long size() {
        if (from > to) {
            return 0;
        }
        return ((to - from) / step) + 1;
    }

    @Override
    public Iterator<String> iterator() {
        return new Iterator<>() {
            private long current = from;

            @Override
            public boolean hasNext() {
                return current <= to;
            }

            @Override
            public String next() {
                if (current > to) {
                    throw new NoSuchElementException();
                }
                String val = padding > 0 ? String.format("%0" + padding + "d", current) : String.valueOf(current);
                current += step;
                return val;
            }
        };
    }

    @Override
    public void reset() {
        // no-op; iterator() creates fresh state
    }

    @Override
    public String label() {
        return "Range " + from + "-" + to + " (" + String.format("%,d", size()) + " items)";
    }
}
