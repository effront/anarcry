
Resumo de Compatibilidade da Stack (Outubro/2026)


Tipo de Teste (AnarCry)	Modelo Recomendado	Vantagem no OpenCode
Auditoria PQC e TLS	Qwen3.8 Max	Melhor entendimento da extensão supported_groups e JEP 496/497 nativa do Java 27.
Exploração JWT & Probes	DeepSeek V4-Pro	Excelente capacidade de reconstrução matemática de payloads criptográficos.
Varrer Injeções (XXE, SSTI, SSRF)	DeepSeek V4.1 Flash	Rápido, econômico por token e eficiente em análises comparativas de respostas brutas.
Triagem de IDOR (BOLA)	GLM-5.3-Flash	Lida perfeitamente com o contexto multi-token simultâneo e payloads de controle de acesso.


Dica de Execução Técnica

Como o AnarCry possui suporte completo a HTTP/2 Connection Pooling (HttpClientFactory) e exporta relatórios estruturados diretamente para Markdown e JSON por ordem de severidade, configure o OpenCode para operar em modo Headless CLI (via CliScanRunner). Isso permite que a IA execute o binário em background na sua VPS ou máquina local, consuma o arquivo .json gerado pelo ReportEngine e monte automaticamente uma tabela de triagem de vulnerabilidades no seu terminal
