package gg.effront.anarcry.fuzzer;

import java.util.Iterator;
import java.util.List;

public final class InlinePayloadSource implements PayloadSource {

    private final List<String> payloads;

    public InlinePayloadSource(String text) {
        this.payloads = text.lines().filter(l -> !l.isEmpty()).toList();
    }

    public InlinePayloadSource(List<String> payloads) {
        this.payloads = List.copyOf(payloads);
    }

    @Override
    public long size() {
        return payloads.size();
    }

    @Override
    public Iterator<String> iterator() {
        return payloads.iterator();
    }

    @Override
    public void reset() {
        // no-op
    }

    @Override
    public String label() {
        return "Inline (" + payloads.size() + " items)";
    }
}
