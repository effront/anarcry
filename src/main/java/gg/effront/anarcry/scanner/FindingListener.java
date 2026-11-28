package gg.effront.anarcry.scanner;

import gg.effront.anarcry.model.Finding;

/**
 * Callback hook invoked for each finding as it is discovered, before
 * deduplication and suppression. Implementations must be thread-safe --
 * findings arrive from parallel scanner modules.
 */
@FunctionalInterface
public interface FindingListener {
    void onFinding(Finding finding);
}
