# SecretScanner-K8s

SecretScanner-K8s é uma ferramenta de segurança e conformidade para detecção estática e dinâmica de credenciais expostas, chaves de API e tokens sensíveis em manifestos Kubernetes.

O projeto é estruturado em quatro pilares integrados:
- **Go**: detecta segredos e decide severidades (`critical`, `high`, `medium`, `low`).
- **Python**: interpreta o contrato JSON v1.0 e apresenta relatórios visuais HTML estáticos e resumos estruturados.
- **GitHub Actions**: integra à esteira de CI/CD e publica diagnósticos SARIF no GitHub Code Scanning.
- **Kubernetes**: aplica a política de admissão no cluster e bloqueia o deployment de manifestos vulneráveis.

---

## Demonstração Rápida Local

Execute o fluxo completo de compilação, varredura de fixtures e geração de relatório com quatro comandos:

```bash
# 1. Executar testes automatizados (Go e Python)
make test

# 2. Compilar os binários estáticos locais
make build

# 3. Executar varredura nos manifestos de teste (gerando JSON e SARIF)
make scan-fixtures

# 4. Gerar relatório visual HTML autocontido
make report
```

O relatório HTML gerado em `scan-output/report.html` é 100% estático e autocontido (CSS inline, sem dependências de rede, com proteção contra XSS e sem vazamento de segredos).

---

## Validação no Kubernetes (Kind / Minikube)

```bash
# 1. Gerar certificados TLS e aplicar manifests do Admission Webhook
make certs
kubectl apply -f deploy/00-namespace.yaml
kubectl apply -f deploy/01-serviceaccount.yaml
kubectl apply -f deploy/02-secret-tls.yaml
kubectl apply -f deploy/03-deployment.yaml
kubectl apply -f deploy/04-service.yaml
kubectl apply -f deploy/05-validatingwebhook.yaml

# 2. Testar bloqueio de manifesto vulnerável
kubectl apply -f examples/vulnerable/deployment.yaml
# Resultado no kubectl: Error from server (Forbidden): admission webhook "validate.secretscanner.k8s" denied the request

# 3. Testar admissão de manifesto seguro
kubectl apply -f examples/clean/deployment.yaml
# Resultado no kubectl: deployment.apps/order-service created
```

### Protocolo de Admissão e Respostas do Webhook:
- **Camada de Transporte HTTP**: A requisição do Kubernetes API Server para o endpoint `/validate` retorna sempre **HTTP 200 OK**.
- **Envelope de Decisão (`AdmissionResponse`)**:
  - Em caso de bloqueio: `response.allowed: false` e `response.status.code: 403` (Forbidden).
  - Em caso de aceite: `response.allowed: true`.
- **Cliente (`kubectl`)**: Observa a mensagem de recusa formal `Error from server (Forbidden)` sem qualquer exposição de segredos nos logs.

---

## Arquitetura e Contrato de Dados

```
                      +-----------------------------+
                      |   Kubernetes Manifests      |
                      |   (YAML / Multi-Doc / Data) |
                      +--------------+--------------+
                                     |
                                     v
                 +---------------------------------------+
                 |       SecretScanner Engine (Go)       |
                 |  - Regex Detectors (AWS, GCP, SSH)    |
                 |  - Shannon Entropy Analysis           |
                 |  - Base64 Secret.data In-Memory       |
                 |  - Hierarchical Deduplication         |
                 +-------------------+-------------------+
                                     |
                  +------------------+------------------+
                  |                                     |
                  v                                     v
       +--------------------+                +--------------------+
       | Standard JSON v1.0 |                |    SARIF Report    |
       |  (Strict Contract) |                | (GitHub CodeScan)  |
       +----------+---------+                +--------------------+
                  |
                  v
       +--------------------+
       |  Python Reporter   |
       |  - Jinja2 HTML     |
       |  - JSON Summary    |
       +--------------------+
```

---

## Detecção e Regras Nativas

| Regra ID | Descrição | Severidade Padrão | Confiança |
| :--- | :--- | :--- | :--- |
| `internal.aws-access-key-id` | AWS Access Key ID (`AKIA...`) | Critical | High |
| `internal.aws-secret-access-key` | AWS Secret Access Key em contexto sensível | Critical | High |
| `internal.google-api-key` | Google Cloud API Key (`AIza...`) | Critical | High |
| `internal.ssh-private-key` | Cabeçalhos de chave privada OpenSSH / RSA | Critical | High |
| `internal.jwt-token` | JSON Web Tokens codificados em Base64 | Critical | High |
| `internal.sensitive-env-var` | Chaves sensíveis (`PASSWORD`, `TOKEN`) em plain env | High | High |
| `internal.shannon-entropy` | Strings de alta entropia (Shannon $H \ge 4.5$) | Medium | Medium |

---

## Garantia de Segurança e Anti-Leak

- **Mascaramento Proativo**: Todos os findings produzidos pelos detectores e cobertos pelos testes são mascarados antes de serem serializados ou exibidos (`AKIA************MPLE`).
- **Isolamento de Memória**: O scanner processa manifests e campos `Secret.data` exclusivamente em memória, sem persistir segredos descriptografados em arquivos temporários de disco.
- **Privilégios Mínimos**: O webhook de admissão não consulta nem lê segredos existentes no etcd do cluster.
- Detalhes completos sobre o Threat Model STRIDE estão documentados em [SECURITY.md](SECURITY.md).

---

## Maturidade do Projeto e Publicação

O projeto está pronto para publicação no GitHub, demonstração técnica e validação em ambiente local ou de homologação. A adoção em produção ainda requer testes operacionais contínuos, revisão da infraestrutura de certificados TLS (ex: cert-manager), calibração de `failurePolicy`, observabilidade e validação em um cluster controlado.

Release inicial: `v0.1.0`.

---

## Licença

Distribuído sob licença Apache 2.0. Consulte [LICENSE](LICENSE) para obter mais informações.
