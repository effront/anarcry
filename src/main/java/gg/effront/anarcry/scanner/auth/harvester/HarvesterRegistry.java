package gg.effront.anarcry.scanner.auth.harvester;

import gg.effront.anarcry.scanner.auth.AuthProvider;

import java.util.List;
import java.util.Optional;
import java.util.Set;

public final class HarvesterRegistry {

    private static final List<Harvester> HARVESTERS = List.of(new FirebaseHarvester());

    private static final Set<AuthProvider> SUPPORTED_PROVIDERS = HARVESTERS.stream().map(Harvester::provider)
            .collect(java.util.stream.Collectors.toUnmodifiableSet());

    private HarvesterRegistry() {
    }

    public static boolean isSupported(AuthProvider provider) {
        return SUPPORTED_PROVIDERS.contains(provider);
    }

    public static Optional<Harvester> forProvider(AuthProvider provider) {
        return HARVESTERS.stream().filter(h -> h.provider() == provider).findFirst();
    }

    public static Optional<Harvester> detect(String targetUrl, String pageSource) {
        return HARVESTERS.stream().filter(h -> h.canHandle(targetUrl, pageSource)).findFirst();
    }
}
