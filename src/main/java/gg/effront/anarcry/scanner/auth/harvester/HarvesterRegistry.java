package gg.effront.anarcry.scanner.auth.harvester;

import gg.effront.anarcry.scanner.auth.AuthProvider;

import java.util.List;
import java.util.Optional;

public final class HarvesterRegistry {

    private static final List<Harvester> HARVESTERS = List.of(new FirebaseHarvester());

    private HarvesterRegistry() {
    }

    public static Optional<Harvester> forProvider(AuthProvider provider) {
        return HARVESTERS.stream().filter(h -> h.provider() == provider).findFirst();
    }

    public static Optional<Harvester> detect(String targetUrl, String pageSource) {
        return HARVESTERS.stream().filter(h -> h.canHandle(targetUrl, pageSource)).findFirst();
    }
}
