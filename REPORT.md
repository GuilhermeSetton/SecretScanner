# Relatório Técnico de Engenharia, Qualidade e Arquitetura
**SecretScanner-K8s: Scanner Estático e Dinâmico de Segredos em Manifestos Kubernetes**

---

## 1. Sumário Executivo do Projeto

O SecretScanner-K8s é uma solução de DevSecOps completa construída sobre quatro pilares interdependentes:
1. **Go Core Engine & CLI (`cmd/secretscanner`, `internal/scanner`, `internal/detectors`)**: Motor de análise estática e em memória de manifestos YAML baseado em nós AST (`gopkg.in/yaml.v3`).
2. **Camada de Apresentação em Python (`python/report_generator`)**: Gerador independente de relatórios estáticos em HTML e sumários JSON estruturados via Jinja2 com autoescape completo.
3. **GitHub Action & CI/CD (`action.yml`, `.github/workflows`)**: Integração automatizada com GitHub Code Scanning via SARIF e upload de artefatos.
4. **Kubernetes Admission Controller Webhook (`cmd/admission-webhook`, `internal/admission`, `deploy/`)**: Serviço HTTP/HTTPS leve e concorrente para interceptação e validação pré-admissão no cluster Kubernetes.

---

## 2. Métricas de Testes e Cobertura

### Go Test Suite (`go test -v -cover ./...`)

```text
ok      github.com/secretscanner/secretscanner-k8s/cmd/admission-webhook    coverage: 68.1% of statements
ok      github.com/secretscanner/secretscanner-k8s/cmd/secretscanner        coverage: 87.0% of statements
ok      github.com/secretscanner/secretscanner-k8s/internal/admission       coverage: 76.0% of statements
ok      github.com/secretscanner/secretscanner-k8s/internal/detectors       coverage: 84.6% of statements
ok      github.com/secretscanner/secretscanner-k8s/internal/report          coverage: 71.4% of statements
ok      github.com/secretscanner/secretscanner-k8s/internal/scanner         coverage: 84.9% of statements
ok      github.com/secretscanner/secretscanner-k8s/pkg/rules                coverage: 76.4% of statements
```
- **Total de Testes Go**: 35 testes unitários e de integração aprovados (100% PASS).
- **Go Vet / Análise Estática**: 0 erros, 0 avisos.

### Python Test Suite (`pytest python`)
- **Total de Testes Python**: 22 testes unitários e de integração aprovados (100% PASS).
- **Tempo de Execução**: 0.12s.
- **Cobertura**: Validação de payload estrito (`additionalProperties: false`), coerência de contagens derivadas, escape XSS de vetores maliciosos (`<script>`, `<img>`, `<svg>`), e interface CLI.

---

## 3. Matriz de Status dos Ambientes de Execução

| Componente / Validação | Status de Execução | Observações |
| :--- | :--- | :--- |
| **Testes Unitários Go (`go test -v -cover`)** | **Executado com sucesso** | Todos os pacotes validados localmente. |
| **Testes Unitários Python (`pytest python`)** | **Executado com sucesso** | 22 testes de validação, agregação e HTML. |
| **Instalação do Pacote Python (`pip install -e python`)** | **Executado com sucesso** | Pacote instalado via `pyproject.toml`. |
| **Geração de Certificados TLS (`go run ./cmd/gencerts`)** | **Executado com sucesso** | Geração e injeção automática em manifests. |
| **Validação de Sintaxe YAML de Manifestos e CI** | **Executado com sucesso** | Todos os arquivos em `deploy/` e `.github/`. |
| **Detector de Corrida Go (`go test -v -race`)** | **Não executado neste ambiente** | Requer CGO/GCC; configurado no workflow CI Linux. |
| **Construção de Imagens Docker (`docker build`)** | **Não executado neste ambiente** | Daemon Docker Desktop desligado no host local. |
| **Execução de Workflow no GitHub Actions** | **Não executado neste ambiente** | Requer runner remoto no GitHub. |
| **Upload de SARIF no GitHub Code Scanning** | **Não executado neste ambiente** | Requer permissão remota `security-events: write`. |

---

## 4. Tabela Técnica de Limitações Arquiteturais

| ID | Limitação Técnica | Causa Raiz / Trade-off | Mitigação / Comportamento no Sistema |
| :--- | :--- | :--- | :--- |
| **LIM-01** | Segredos interpolados via Helm / Kustomize | O scanner avalia strings estáticas do YAML. Variáveis não renderizadas (ex: `{{ .Values.secret }}`) contêm apenas texto literal de template. | O scanner avalia a saída final gerada por `helm template` ou `kustomize build` antes da submissão ao cluster. |
| **LIM-02** | Falsos positivos em dados aleatórios de alta entropia | Hashes criptográficos e IDs UUIDv4 podem atingir Shannon Entropy $H \ge 4.5$. | Heurísticas contextuais filtram UUIDs e nomes comuns. Findings por entropia são marcados com severidade `Medium` e confiança `Medium`. |
| **LIM-03** | Segredos divididos em múltiplos nós | Credenciais divididas ou construídas dinamicamente via scripts de inicialização (`initContainers`) não formam um escalar contíguo. | O detector de variáveis de ambiente (`sensitive-env-var`) inspeciona o nome da variável mesmo se o valor for concatenado. |
| **LIM-04** | Formatos não-YAML (JSON / INI dentro de ConfigMaps) | Arquivos de configuração complexos serializados como blocos de texto único em ConfigMaps exigem sub-parsers específicos. | O scanner aplica análise regex e varredura de entropia linha a linha em blocos de texto literais (`\|`, `>`). |
| **LIM-05** | Limite de tamanho de arquivo (10 MB Go / 50 MB Python) | Proteção contra ataques de negação de serviço (DoS via YAML bombs / memory exhaustion). | Arquivos que excedem o limite são rejeitados com erro descritivo em `errors` sem derrubar o processo. |
| **LIM-06** | Namespaces ignorados sem análise profunda | Operações em namespaces do sistema (`kube-system`, `secretscanner-system`) são aceitas para evitar bloqueio acidental do control plane. | Política configurável via `-ignore-namespaces`; o webhook permite o recurso sem registrar dados sensíveis nos logs. |
| **LIM-07** | Ausência de leitura de Segredos existentes no cluster | Por design de segurança (Least Privilege), o webhook não possui permissões RBAC para consultar secrets armazenados no etcd. | O webhook atua exclusivamente como gatekeeper preventivo sobre o objeto submetido no evento `CREATE`/`UPDATE`. |

---

## 5. Garantias de Anti-Leak e Segurança de Dados

1. **Mascaramento Determinístico Imediato**:
   - Todo segredo identificado tem seu valor mascarado no momento da captura (`MaskSecret`).
   - Relatórios JSON, SARIF, HTML e mensagens de admissão expõem apenas a representação truncada (`AKIA************MPLE`).
2. **Processamento Estritamente em Memória**:
   - Manifestos e dados de `Secret.data` (Base64) são decodificados em buffers temporários e nunca persistem em disco.
3. **Execução com Privilégios Mínimos**:
   - O Admission Webhook opera sob usuário não-root (`UID 10001:10001`), `readOnlyRootFilesystem: true`, e sem permissões de leitura no cluster Kubernetes.
