package gg.effront.anarcry.harness;

import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.scanner.ScanConfig;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.web.infra.InfraModule;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class InfraModuleTest {

    @Test
    void infraScanVps() throws Exception {
        String target = "https://api.prostaff.gg";
        ScanContext ctx = new ScanContext(target, "", "", Set.of("Infra"),
                new ScanConfig(0, "", Set.of(), List.of(), ""), r -> {});

        InfraModule module = new InfraModule();
        List<Finding> findings = module.scan(ctx, msg -> System.out.println(msg));

        System.out.println("\n=== FINDINGS (" + findings.size() + ") ===");
        for (Finding f : findings) {
            System.out.println("[" + f.severity() + "] " + f.title());
            System.out.println("  Evidence: " + f.evidence());
            System.out.println("  PoC: " + f.reproduction());
            System.out.println();
        }

        assertNotNull(findings);
    }
}
