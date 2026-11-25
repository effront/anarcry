package gg.effront.anarcry.fuzzer;

@FunctionalInterface
public interface PayloadProcessor {

    /**
     * Transforms a payload before injection. Returns null to skip this payload
     * entirely.
     */
    String process(String input);
}
