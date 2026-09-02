# SecretScanner-K8s

[English](README.md) | [Português (Brasil)](README.pt-BR.md)

[![CI](https://github.com/GuilhermeSetton/SecretScanner/actions/workflows/test.yml/badge.svg)](https://github.com/GuilhermeSetton/SecretScanner/actions/workflows/test.yml)
[![Security Scan](https://github.com/GuilhermeSetton/SecretScanner/actions/workflows/security-scan.yml/badge.svg)](https://github.com/GuilhermeSetton/SecretScanner/actions/workflows/security-scan.yml)
[![Relatório de Exemplo](https://github.com/GuilhermeSetton/SecretScanner/actions/workflows/pages.yml/badge.svg)](https://guilhermesetton.github.io/SecretScanner/)
[![Licença](https://img.shields.io/github/license/GuilhermeSetton/SecretScanner)](LICENSE)

**Impeça que credenciais expostas em manifestos Kubernetes cheguem ao Git, à CI ou ao cluster.**

Manifestos Kubernetes frequentemente misturam chaves de API, tokens de acesso, senhas e secrets codificados com configurações comuns. Um único valor vazado pode entrar no histórico do Git, aparecer em logs da CI ou ser implantado antes que alguém perceba.

O SecretScanner-K8s ajuda equipes de desenvolvimento, plataforma e segurança a detectar essas credenciais antes do deployment. Ele analisa manifestos YAML localmente ou na CI, mascara todo valor reportado, classifica a severidade e pode bloquear workloads vulneráveis por meio de um admission webhook do Kubernetes.

- Detecta chaves AWS e Google Cloud, chaves privadas SSH, JWTs, variáveis de ambiente sensíveis e strings suspeitas de alta entropia.
- Produz relatórios em texto, JSON, SARIF e HTML self-contained sem expor o valor detectado.
- Integra desenvolvimento local, GitHub Code Scanning e bloqueio no momento da admissão.

<p align="center">
  <img src="docs/demo.gif" alt="SecretScanner-K8s encontra cinco credenciais mascaradas em manifestos Kubernetes vulneráveis" width="900">
</p>

Um comando. Cinco achados. Todo valor detectado permanece mascarado.

---

## Início rápido

Pré-requisitos: [Git](https://git-scm.com/) e [Docker](https://docs.docker.com/get-docker/) com Docker Compose.

Depois de clonar o repositório, execute um comando:

```bash
docker compose run --build --rm quickstart
```

Partindo de um diretório vazio:

```bash
git clone https://github.com/GuilhermeSetton/SecretScanner.git && cd SecretScanner && docker compose run --build --rm quickstart
```

O quickstart compila para a arquitetura da máquina, analisa manifestos Kubernetes intencionalmente vulneráveis e imprime achados mascarados. O exit code esperado `1`, que indica detecções, é tratado como sucesso; falhas operacionais continuam sendo propagadas.

Arquivos gerados:

- `scan-output/quickstart-result.json`
- `scan-output/quickstart-report.html`

As duas saídas contêm apenas matches mascarados. O relatório HTML é self-contained e abre sem conexão de rede.

Veja o mesmo formato no [relatório de exemplo publicado](https://guilhermesetton.github.io/SecretScanner/). A página é reconstruída e publicada automaticamente a partir de dados fictícios sempre que arquivos relevantes mudam na branch `main`.

---

## Validação no Kubernetes (Kind / Minikube)

```bash
# 1. Gerar certificados TLS e aplicar os manifestos do admission webhook
make certs
kubectl apply -f deploy/00-namespace.yaml
kubectl apply -f deploy/01-serviceaccount.yaml
kubectl apply -f deploy/02-secret-tls.yaml
kubectl apply -f deploy/03-deployment.yaml
kubectl apply -f deploy/04-service.yaml
kubectl apply -f deploy/05-validatingwebhook.yaml

# 2. Verificar o bloqueio de um manifesto vulnerável
kubectl apply -f examples/vulnerable/deployment.yaml
# Resultado: Error from server (Forbidden): admission webhook "validate.secretscanner.k8s" denied the request

# 3. Verificar a admissão de um manifesto seguro
kubectl apply -f examples/clean/deployment.yaml
# Resultado: deployment.apps/order-service created
```

### Protocolo de admissão e respostas do webhook

- **Transporte HTTP**: A requisição do Kubernetes API Server ao endpoint `/validate` sempre recebe **HTTP 200 OK**.
- **Envelope de decisão (`AdmissionResponse`)**:
  - Workload bloqueado: `response.allowed: false` e `response.status.code: 403` (Forbidden).
  - Workload aceito: `response.allowed: true`.
- **Cliente (`kubectl`)**: Exibe a recusa formal `Error from server (Forbidden)` sem expor credenciais nos logs.

---

## Arquitetura e contrato de dados

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

## Regras nativas de detecção

| ID da regra | Descrição | Severidade padrão | Confiança |
| :--- | :--- | :--- | :--- |
| `internal.aws-access-key-id` | AWS Access Key ID (`AKIA...`) | Critical | High |
| `internal.aws-secret-access-key` | AWS Secret Access Key em contexto sensível | Critical | High |
| `internal.google-api-key` | Google Cloud API Key (`AIza...`) | Critical | High |
| `internal.ssh-private-key` | Cabeçalhos de chave privada OpenSSH / RSA | Critical | High |
| `internal.jwt-token` | JSON Web Tokens codificados em Base64 | Critical | High |
| `internal.sensitive-env-var` | Nomes sensíveis (`PASSWORD`, `TOKEN`) em variáveis de ambiente em texto puro | High | High |
| `internal.shannon-entropy` | Strings de alta entropia (Shannon $H \ge 4.5$) | Medium | Medium |

### Falsos positivos de entropia

A regra de entropia é auxiliar: só roda em contextos sensíveis, e o match é descartado
quando o valor tem uma forma que nunca guarda credencial — chaves públicas e
certificados, referências a gerenciadores de segredo (ARNs da AWS, caminhos do Vault,
nomes de recurso do GCP), URLs sem credencial embutida, hashes de senha `crypt(3)` e
PHC, data URIs e templates Helm ou envsubst não resolvidos. As regras de padrão
específico não são afetadas: uma credencial real encontrada dentro de uma dessas formas
continua sendo reportada pela regra própria.

Para silenciar valores específicos dos seus manifestos, use `-entropy-allow` com uma
expressão regular. A flag pode ser repetida:

```bash
secretscanner -dir ./manifests -entropy-allow '^registry\.internal/' -entropy-allow '^build-id-'
```

### Tipografia e assets do relatório

O relatório HTML embute duas tipografias como base64 WOFF2 — [Archivo Narrow](https://github.com/Omnibus-Type/Archivo)
e [Sometype Mono](https://github.com/googlefonts/sometype-mono), ambas SIL OFL 1.1, com as licenças incluídas em
`python/report_generator/fonts/` — além de duas texturas de papel. Nada é buscado em tempo de execução: o relatório
renderiza igual offline, dentro de um visualizador de artefato de CI e no GitHub Pages. O sistema visual está
documentado em [DESIGN.md](DESIGN.md).

---

## Garantias de segurança e anti-leak

- **Mascaramento proativo**: Todo finding coberto pelos testes é mascarado antes da serialização ou exibição (`AKIA************MPLE`).
- **Isolamento de memória**: O scanner processa manifestos e campos `Secret.data` em memória, sem persistir credenciais decodificadas em arquivos temporários no disco.
- **Privilégio mínimo**: O admission webhook não consulta nem lê secrets existentes no etcd do cluster.
- **Self-scan na CI**: O projeto analisa todos os arquivos YAML do próprio repositório e falha em achados fora das fixtures de teste explicitamente vulneráveis.
- O threat model STRIDE completo está documentado em [SECURITY.md](SECURITY.md).

---

## Maturidade do projeto

O projeto está pronto para publicação no GitHub, demonstrações técnicas e validação em ambientes locais ou de homologação. A adoção em produção ainda exige testes operacionais contínuos, revisão da infraestrutura de certificados TLS (por exemplo, cert-manager), calibração de `failurePolicy`, observabilidade e validação em um cluster controlado.

Release inicial: `v0.1.0`.

---

## Licença

Distribuído sob a licença Apache 2.0. Consulte [LICENSE](LICENSE) para detalhes.
