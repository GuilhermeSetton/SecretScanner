# SecretScanner Report Generator (Python)

Pacote Python responsável por interpretar, validar e apresentar os resultados de varredura gerados pelo SecretScanner-K8s em Go.

## Papel na Arquitetura

- **Go**: detecta segredos e decide severidades.
- **Python**: interpreta o contrato JSON, valida o schema, agrega estatísticas e gera relatórios visuais (HTML estático autocontido) ou sumários JSON.

O módulo Python não executa varredura de arquivos nem reimplementa regras de segurança; ele atua estritamente como camada de apresentação e agregação.

## Instalação

```bash
pip install .
```

Ou em modo de desenvolvimento:

```bash
pip install -e ".[dev]"
```

## Uso via CLI

Gerar relatório HTML estático:

```bash
python -m report_generator --input scan.json --output report.html --format html
```

Gerar resumo estruturado em JSON:

```bash
python -m report_generator --input scan.json --output summary.json --format json
```

## Execução de Testes

```bash
pytest
```
