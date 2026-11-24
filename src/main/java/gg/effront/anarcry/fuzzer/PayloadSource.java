package gg.effront.anarcry.fuzzer;

import java.util.Iterator;

public interface PayloadSource {

    long size();

    Iterator<String> iterator();

    void reset();

    String label();
}
