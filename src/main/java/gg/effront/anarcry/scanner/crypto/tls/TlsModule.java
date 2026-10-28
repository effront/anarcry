package gg.effront.anarcry.scanner.crypto.tls;

import gg.effront.anarcry.model.CvssCalculator;
import gg.effront.anarcry.model.CweRegistry;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.Scanner;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

public class TlsModule implements Scanner {

    @Override
    public String id() {
        return "TLS";
    }

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        String _cweId = CweRegistry.cweId(id());
        String _cweTitle = CweRegistry.cweTitle(id());
        String _cveVector = CweRegistry.cvssVector(id());
        double _score = CvssCalculator.calculate(_cveVector);
        List<Finding> results = new ArrayList<>();
        if (!ctx.isHttps()) {
            log.accept("[!] TLS: alvo não é HTTPS -- módulo TLS ignorado");
            return results;
        }
        results.addAll(new TlsVersionProbe().probe(ctx, log));
        results.addAll(new CipherSuiteProbe().probe(ctx, log));
        results.addAll(new CertificateProbe().probe(ctx, log));
        return results;
    }
}
