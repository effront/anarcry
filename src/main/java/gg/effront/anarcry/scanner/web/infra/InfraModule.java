package gg.effront.anarcry.scanner.web.infra;

import gg.effront.anarcry.model.CvssCalculator;
import gg.effront.anarcry.model.CweRegistry;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.Scanner;
import gg.effront.anarcry.scanner.util.HttpClientFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.stream.Collectors;

public class InfraModule implements Scanner {

    private record PortInfo(int port, String service) {
    }

    private record PanelProbe(int port, String path, String[] indicators, String name, Severity severity) {
    }

    private record NmapScan(List<Integer> openPorts, Map<Integer, String> serviceLabels,
            Map<Integer, String> scriptOutputs, String osGuess) {
    }

    private static final List<PortInfo> PROBE_PORTS = List.of(new PortInfo(22, "SSH"), new PortInfo(2375, "Docker API"),
            new PortInfo(2376, "Docker API TLS"), new PortInfo(2379, "etcd"), new PortInfo(3000, "Grafana"),
            new PortInfo(4848, "GlassFish Admin"), new PortInfo(5601, "Kibana"), new PortInfo(6379, "Redis"),
            new PortInfo(8000, "Admin Panel"), new PortInfo(8080, "Jenkins/Tomcat/Spring"),
            new PortInfo(8443, "HTTPS Alt"), new PortInfo(8500, "Consul"), new PortInfo(8888, "Jupyter"),
            new PortInfo(9000, "Portainer/SonarQube"), new PortInfo(9090, "Prometheus"),
            new PortInfo(9200, "Elasticsearch"), new PortInfo(9300, "Elasticsearch Cluster"),
            new PortInfo(10250, "Kubelet"), new PortInfo(15672, "RabbitMQ Management"), new PortInfo(27017, "MongoDB"),
            new PortInfo(50070, "Hadoop NameNode"));

    private static final List<PanelProbe> PANEL_PROBES = List.of(
            new PanelProbe(2375, "/version", new String[]{"\"Version\"", "\"ApiVersion\""},
                    "Docker API unauthenticated", Severity.CRITICAL),
            new PanelProbe(3000, "/api/health", new String[]{"\"database\":"}, "Grafana", Severity.HIGH),
            new PanelProbe(3000, "/", new String[]{"Grafana"}, "Grafana", Severity.HIGH),
            new PanelProbe(5601, "/", new String[]{"Kibana"}, "Kibana", Severity.HIGH),
            new PanelProbe(8000, "/login", new String[]{"Coolify", "coolify_session"}, "Coolify", Severity.HIGH),
            new PanelProbe(8080, "/", new String[]{"X-Jenkins", "Jenkins"}, "Jenkins", Severity.HIGH),
            new PanelProbe(8080, "/actuator/health", new String[]{"\"status\":\"UP\""}, "Spring Boot Actuator",
                    Severity.HIGH),
            new PanelProbe(8080, "/", new String[]{"Apache Tomcat"}, "Tomcat", Severity.MEDIUM),
            new PanelProbe(8500, "/v1/status/leader", new String[]{"."}, "Consul unauthenticated", Severity.CRITICAL),
            new PanelProbe(8888, "/api/kernels", new String[]{"kernels", "kernel_id"}, "Jupyter unauthenticated",
                    Severity.CRITICAL),
            new PanelProbe(9000, "/api/status", new String[]{"\"Version\":"}, "Portainer", Severity.HIGH),
            new PanelProbe(9090, "/api/v1/targets", new String[]{"activeTargets"}, "Prometheus unauthenticated",
                    Severity.HIGH),
            new PanelProbe(9200, "/", new String[]{"cluster_name", "\"version\""}, "Elasticsearch unauthenticated",
                    Severity.CRITICAL),
            new PanelProbe(10250, "/pods", new String[]{"\"kind\":\"PodList\""}, "Kubelet unauthenticated",
                    Severity.CRITICAL),
            new PanelProbe(15672, "/", new String[]{"RabbitMQ"}, "RabbitMQ Management", Severity.HIGH),
            new PanelProbe(50070, "/jmx", new String[]{"\"name\":"}, "Hadoop NameNode", Severity.HIGH));

    @Override
    public String id() {
        return "Infra";
    }

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        List<Finding> findings = new ArrayList<>();

        String _cweId = CweRegistry.cweId(id());
        String _cweTitle = CweRegistry.cweTitle(id());
        String _cveVector = CweRegistry.cvssVector(id());
        double _score = CvssCalculator.calculate(_cveVector);

        String host = ctx.host();
        if (!host.matches("[a-zA-Z0-9._\\-]{1,253}")) {
            log.accept("[!] Infra: host invalido — scan cancelado");
            return findings;
        }
        String portList = PROBE_PORTS.stream().map(p -> String.valueOf(p.port())).collect(Collectors.joining(","));

        List<Integer> openPorts;
        NmapScan nmapScan = null;

        if (nmapAvailable()) {
            boolean root = isRoot();
            log.accept("[~] Infra: nmap detectado"
                    + (root ? " (root — SYN scan + OS detection)" : " (connect scan + service detection)"));
            try {
                nmapScan = runNmap(host, portList, root, log);
                openPorts = nmapScan.openPorts();
                log.accept("[~] Infra: nmap encontrou " + openPorts.size() + " porta(s) abertas");
                if (!nmapScan.osGuess().isBlank()) {
                    log.accept("[~] Infra: OS: " + nmapScan.osGuess());
                    findings.add(Finding.of("Infra", host, "OS fingerprint detectado: " + nmapScan.osGuess(),
                            Severity.INFO, "nmap OS detection: " + nmapScan.osGuess(),
                            "Informacao de OS exposta via fingerprint de rede"
                                    + " — util para targeting de exploits especificos de versao",
                            "nmap -O -Pn " + host, "Considerar TCP stack hardening para dificultar OS fingerprinting",
                            _cweId, _cweTitle, _cveVector, _score));
                }
            } catch (Exception e) {
                log.accept("[~] Infra: nmap falhou (" + e.getMessage() + ") — fallback connect scan");
                openPorts = connectScan(host, log);
            }
        } else {
            log.accept("[~] Infra: nmap nao encontrado — connect scan (" + PROBE_PORTS.size() + " portas)");
            openPorts = connectScan(host, log);
        }

        if (openPorts.isEmpty()) {
            log.accept("[+] Infra: nenhuma porta de infra exposta detectada");
            return findings;
        }

        log.accept("[~] Infra: " + openPorts.size() + " porta(s) abertas — fingerprinting...");

        // SSH
        if (openPorts.contains(22)) {
            String banner = (nmapScan != null && nmapScan.serviceLabels().containsKey(22))
                    ? nmapScan.serviceLabels().get(22)
                    : sshBanner(host);

            String authMethods;
            String scriptOut = (nmapScan != null) ? nmapScan.scriptOutputs().getOrDefault(22, "") : "";
            if (!scriptOut.isBlank()) {
                boolean hasPw = scriptOut.contains("password");
                boolean hasPk = scriptOut.contains("publickey");
                authMethods = hasPk && hasPw
                        ? "publickey,password"
                        : hasPw ? "password" : hasPk ? "publickey" : "unknown";
            } else {
                authMethods = sshAuthMethods(host);
            }

            boolean passwordEnabled = authMethods.contains("password");
            Severity sev = passwordEnabled ? Severity.MEDIUM : Severity.INFO;
            log.accept(passwordEnabled
                    ? "[!] Infra: MEDIUM — SSH aceita senha em " + host + ":22 (" + banner + ")"
                    : "[~] Infra: SSH exposto em " + host + ":22, so publickey (" + banner + ")");
            findings.add(Finding.of("Infra", host + ":22",
                    "SSH exposto — " + (passwordEnabled ? "password auth habilitado" : "publickey only"), sev,
                    "Host: " + host + ":22 | Banner: " + banner + " | Auth methods: " + authMethods,
                    passwordEnabled
                            ? "SSH exposto com autenticacao por senha habilitada"
                                    + " — vulneravel a brute force e credential stuffing"
                            : "SSH exposto publicamente, apenas publickey aceita — risco de brute force baixo",
                    "ssh -o PreferredAuthentications=password -o BatchMode=yes user@" + host,
                    passwordEnabled
                            ? "Desabilitar PasswordAuthentication no sshd_config; restringir acesso por IP ou VPN"
                            : "Considerar restringir acesso SSH por IP ou VPN para reduzir superficie",
                    _cweId, _cweTitle, _cveVector, _score));
        }

        // Redis unauthenticated
        if (openPorts.contains(6379)) {
            String pong = redisPing(host);
            if (pong.startsWith("+PONG")) {
                log.accept("[!!] Infra: CRITICAL — Redis unauthenticated em " + host + ":6379");
                findings.add(Finding.of("Infra", host + ":6379", "Redis exposto sem autenticacao", Severity.CRITICAL,
                        "Host: " + host + ":6379 | PING -> +PONG (sem autenticacao requerida)",
                        "Redis acessivel sem senha — leitura/escrita arbitraria de todas as chaves;"
                                + " possivel RCE via CONFIG SET dir/dbfilename para escrever webshell ou cron",
                        "redis-cli -h " + host + " PING && redis-cli -h " + host + " INFO server",
                        "Configurar requirepass no redis.conf; bind em loopback ou interface interna;"
                                + " bloquear porta 6379 no firewall",
                        _cweId, _cweTitle, _cveVector, _score));
            }
        }

        // MongoDB exposto
        if (openPorts.contains(27017)) {
            log.accept("[!] Infra: HIGH — MongoDB exposto em " + host + ":27017");
            findings.add(Finding
                    .of("Infra", host + ":27017", "MongoDB exposto — porta acessivel externamente", Severity.HIGH,
                            "Host: " + host + ":27017 | porta TCP aberta sem restricao de rede detectada",
                            "MongoDB na porta padrao exposto — verificar se autenticacao esta habilitada;"
                                    + " versoes sem --auth aceitam qualquer conexao",
                            "mongosh --host " + host + " --eval \"db.adminCommand({listDatabases:1})\"",
                            "Habilitar autenticacao (security.authorization: enabled);"
                                    + " bind em loopback; bloquear 27017 no firewall",
                            _cweId, _cweTitle, _cveVector, _score));
        }

        // etcd exposto
        if (openPorts.contains(2379)) {
            log.accept("[!] Infra: CRITICAL — etcd exposto em " + host + ":2379");
            findings.add(Finding.of("Infra", host + ":2379", "etcd exposto — porta acessivel externamente",
                    Severity.CRITICAL, "Host: " + host + ":2379 | porta TCP aberta",
                    "etcd exposto pode conter secrets do Kubernetes (tokens, certs, credenciais de servicos)",
                    "curl http://" + host + ":2379/v3/cluster/member/list",
                    "Restringir acesso ao etcd por firewall; habilitar TLS client auth; nunca expor publicamente",
                    _cweId, _cweTitle, _cveVector, _score));
        }

        // HTTP panel fingerprinting
        HttpClient hc = HttpClientFactory.noRedirect();
        List<String> alreadyReported = new ArrayList<>();

        for (PanelProbe probe : PANEL_PROBES) {
            if (!openPorts.contains(probe.port())) {
                continue;
            }

            String dedupKey = host + ":" + probe.port() + "/" + probe.name();
            if (alreadyReported.contains(dedupKey)) {
                continue;
            }

            for (String scheme : new String[]{"http", "https"}) {
                String url = scheme + "://" + host + ":" + probe.port() + probe.path();
                try {
                    HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(5)).GET()
                            .build();
                    HttpResponse<String> resp = hc.send(req, HttpResponse.BodyHandlers.ofString());
                    String body = resp.body() != null ? resp.body() : "";
                    String headers = resp.headers().map().toString();
                    String combined = body + headers;

                    boolean matched = false;
                    String matchedIndicator = "";
                    for (String indicator : probe.indicators()) {
                        if (combined.contains(indicator)) {
                            matched = true;
                            matchedIndicator = indicator;
                            break;
                        }
                    }

                    if (matched) {
                        alreadyReported.add(dedupKey);
                        log.accept("[!!] Infra: " + probe.severity() + " — " + probe.name() + " em " + url);
                        findings.add(Finding.of("Infra", host + ":" + probe.port(),
                                probe.name() + " exposto sem restricao de rede", probe.severity(),
                                "URL: " + url + " | HTTP " + resp.statusCode() + " | Indicador: " + matchedIndicator,
                                "Painel/servico de administracao acessivel sem restricao de rede — "
                                        + "atacante com acesso ao IP pode autenticar,"
                                        + " explorar ou pivotar para a infra interna",
                                "curl -sk " + url,
                                "Bloquear porta " + probe.port()
                                        + " na interface externa (ufw deny in on <ext-if> to any port " + probe.port()
                                        + "); " + "acessar apenas via VPN ou tunnel SSH",
                                _cweId, _cweTitle, _cveVector, _score));
                        break;
                    }
                } catch (Exception ignored) {
                }
            }
        }

        if (findings.isEmpty()) {
            log.accept("[+] Infra: portas abertas sem servicos criticos identificados");
        }
        return findings;
    }

    // --- nmap integration ---

    private NmapScan runNmap(String host, String portList, boolean root, Consumer<String> log) throws Exception {
        List<String> cmd = new ArrayList<>();
        cmd.add("nmap");
        cmd.add("-Pn");
        cmd.add("--open");
        if (root) {
            cmd.add("-sS");
            cmd.add("-O");
        }
        cmd.add("-sV");
        cmd.add("--script=ssh-auth-methods,banner");
        cmd.add("--host-timeout");
        cmd.add("90s");
        cmd.add("-p");
        cmd.add(portList);
        cmd.add("-oX");
        cmd.add("-");
        cmd.add(host);

        log.accept("[~] Infra: executando: " + String.join(" ", cmd));

        ProcessBuilder pb = new ProcessBuilder(cmd); // nosemgrep
        pb.redirectErrorStream(false);
        Process p = pb.start();

        String xml = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        boolean finished = p.waitFor(120, TimeUnit.SECONDS);
        if (!finished) {
            p.destroyForcibly();
            throw new RuntimeException("nmap timeout");
        }

        return parseNmapXml(xml);
    }

    private NmapScan parseNmapXml(String xml) throws Exception {
        if (xml.isBlank() || !xml.contains("<nmaprun")) {
            throw new RuntimeException("saida nmap invalida ou vazia");
        }

        // nmap inclui <!DOCTYPE nmaprun> -- remover antes de parsear (output proprio,
        // nao externo)
        String cleanXml = xml.replaceAll("<!DOCTYPE[^>]*>", "");

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setExpandEntityReferences(false);
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(new ByteArrayInputStream(cleanXml.getBytes(StandardCharsets.UTF_8)));

        List<Integer> openPorts = new ArrayList<>();
        Map<Integer, String> serviceLabels = new HashMap<>();
        Map<Integer, String> scriptOutputs = new HashMap<>();

        NodeList ports = doc.getElementsByTagName("port");
        for (int i = 0; i < ports.getLength(); i++) {
            Element portEl = (Element) ports.item(i);
            int portId = Integer.parseInt(portEl.getAttribute("portid"));

            NodeList states = portEl.getElementsByTagName("state");
            if (states.getLength() == 0) {
                continue;
            }
            if (!"open".equals(((Element) states.item(0)).getAttribute("state"))) {
                continue;
            }

            openPorts.add(portId);

            NodeList services = portEl.getElementsByTagName("service");
            if (services.getLength() > 0) {
                Element svc = (Element) services.item(0);
                String name = svc.getAttribute("name");
                String product = svc.getAttribute("product");
                String version = svc.getAttribute("version");
                String label = name + (!product.isBlank() ? " " + product : "")
                        + (!version.isBlank() ? " " + version : "");
                serviceLabels.put(portId, label.trim());
            }

            NodeList scripts = portEl.getElementsByTagName("script");
            for (int j = 0; j < scripts.getLength(); j++) {
                Element script = (Element) scripts.item(j);
                String scriptId = script.getAttribute("id");
                if ("ssh-auth-methods".equals(scriptId) || "banner".equals(scriptId)) {
                    scriptOutputs.put(portId, script.getAttribute("output"));
                }
            }
        }

        String osGuess = "";
        NodeList osmatches = doc.getElementsByTagName("osmatch");
        if (osmatches.getLength() > 0) {
            Element osmatch = (Element) osmatches.item(0);
            osGuess = osmatch.getAttribute("name") + " (accuracy: " + osmatch.getAttribute("accuracy") + "%)";
        }

        return new NmapScan(openPorts, serviceLabels, scriptOutputs, osGuess);
    }

    private boolean nmapAvailable() {
        try {
            Process p = new ProcessBuilder("nmap", "--version").start();
            boolean done = p.waitFor(5, TimeUnit.SECONDS);
            return done && p.exitValue() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isRoot() {
        try {
            for (String line : Files.readAllLines(Path.of("/proc/self/status"))) {
                if (line.startsWith("Uid:")) {
                    return "0".equals(line.split("\\s+")[1]);
                }
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    // --- fallback connect scan ---

    private List<Integer> connectScan(String host, Consumer<String> log) {
        List<Integer> openPorts = new ArrayList<>();
        for (PortInfo pi : PROBE_PORTS) {
            if (tcpOpen(host, pi.port())) {
                openPorts.add(pi.port());
                log.accept("[~] Infra: " + pi.port() + "/tcp aberto (" + pi.service() + ")");
            }
        }
        return openPorts;
    }

    private boolean tcpOpen(String host, int port) {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(host, port), 1000);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    private String sshBanner(String host) {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(host, 22), 3000);
            s.setSoTimeout(3000);
            byte[] buf = new byte[256];
            int n = s.getInputStream().read(buf);
            if (n > 0) {
                return new String(buf, 0, n, StandardCharsets.UTF_8).trim();
            }
        } catch (Exception ignored) {
        }
        return "unknown";
    }

    private String sshAuthMethods(String host) {
        try {
            ProcessBuilder pb = new ProcessBuilder("ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=3", "-o",
                    "StrictHostKeyChecking=no", "-o", "PreferredAuthentications=password", "-o",
                    "PubkeyAuthentication=no", "-l", "probe", host);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            p.waitFor();
            int start = out.indexOf('(');
            int end = out.lastIndexOf(')');
            if (start >= 0 && end > start) {
                return out.substring(start + 1, end);
            }
        } catch (Exception ignored) {
        }
        return "unknown";
    }

    private String redisPing(String host) {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(host, 6379), 2000);
            s.setSoTimeout(2000);
            OutputStream out = s.getOutputStream();
            InputStream in = s.getInputStream();
            out.write("PING\r\n".getBytes(StandardCharsets.UTF_8));
            out.flush();
            byte[] buf = new byte[64];
            int n = in.read(buf);
            if (n > 0) {
                return new String(buf, 0, n, StandardCharsets.UTF_8).trim();
            }
        } catch (Exception ignored) {
        }
        return "";
    }
}
