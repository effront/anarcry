package gg.effront.anarcry.scanner;

import gg.effront.anarcry.model.Finding;

import java.util.List;
import java.util.function.Consumer;

public interface Scanner {
    String id();
    List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception;
}
