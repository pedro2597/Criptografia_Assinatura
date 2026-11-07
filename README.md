# Criptografia e Assinatura Digital – XYZW Tecnologia

Trabalho 01 da disciplina MATC99 – Criptografia Aplicada (UFBA).
Felipe Silva Rezende, Pedro Elias Pribanic Fonseca e Gabriell Barreto Santiago dos Santos.

O projeto protege e verifica documentos da empresa fictícia XYZW Tecnologia em duas partes:

- **Parte I – AES-GCM** (`criptografia.py`): cifra um documento com AES-256-GCM, decifra com a chave correta e testa uma chave incorreta e um criptograma alterado em 1 bit.
- **Parte II – Assinaturas e certificados** (`assinatura.py`): assina o documento com RSA-2048 e SHA-256 sob uma CA própria e reproduz três casos:
  - **A:** documento original e certificado confiável.
  - **B:** documento alterado depois de assinado.
  - **C:** assinatura válida, mas com certificado de uma CA não confiável.

O relatório técnico está em [`relatorio.html`](relatorio.html). Abra no navegador e use Ctrl+P > Salvar como PDF, em papel A4.

## Estrutura

| Arquivo | Função |
|---|---|
| `documento.txt` | Proposta comercial fictícia usada nos testes |
| `criptografia.py` | Menu interativo da Parte I (AES-GCM) |
| `assinatura.py` | Menu interativo da Parte II (assinatura, CAs e verificação) |
| `executar_testes.sh` | Roteiro que executa todos os experimentos e confere os resultados |
| `relatorio.html` | Relatório técnico no padrão ABNT |

## Requisitos

- Python 3.10 ou superior com a biblioteca `cryptography`:
  ```bash
  pip install cryptography
  ```
- OpenSSL no PATH. No Windows, o Git for Windows já traz o Git Bash e o OpenSSL.

## Reprodução automatizada (recomendada)

No Git Bash (Windows) ou em um terminal Linux/macOS:

```bash
git clone https://github.com/pedro2597/Criptografia_Assinatura.git
cd Criptografia_Assinatura
bash executar_testes.sh
```

O roteiro:

1. Recria a pasta `execucao_testes/` e copia `documento.txt` para ela.
2. Executa a Parte I e os casos A, B e C, enviando ao menu as mesmas opções que um usuário digitaria.
3. Mostra, em cada passo, **o que está sendo verificado** e marca `[OK]` ou `[FALHA]`.
4. Confirma as assinaturas e as cadeias de forma independente com `openssl dgst -verify` e `openssl verify`.
5. Termina com o total de verificações aprovadas: o esperado é `44/44`, com código de saída 0.

Os registros de cada passo ficam em `execucao_testes/evidencias/`. Os artefatos gerados ficam em `execucao_testes/arquivos_criptografados/` e `execucao_testes/assinaturas_digitais/`.

## Reprodução manual

Os programas gravam em pastas relativas ao diretório atual e não sobrescrevem resultados anteriores. Por isso, use uma pasta vazia:

```bash
mkdir teste && cp documento.txt teste/ && cd teste
```

Quando o menu pedir para selecionar o documento, digite `1`.

### Parte I – `python ../criptografia.py`

| Experimento | Opções do menu | Resultado esperado |
|---|---|---|
| Cifrar | `1`, informar `documento.txt` | Cria `arquivos_criptografados/documento/` com o `.aes`, a chave, o nonce e o nome original |
| Controle de integridade | `5` | "Sucesso! Integridade confirmada." |
| Chave correta | `2` | Gera `recuperado_documento.txt`, idêntico ao original |
| Chave incorreta | `3` | "Falha! Chave incorreta detectada." |
| Alterar 1 bit do criptograma | `4` | Gera `documento_adulterado.aes` |
| Detectar a alteração | `5` | "Falha! Adulteração detectada pelo AES-GCM." |

### Parte II – `python ../assinatura.py`

| Experimento | Opções do menu | Resultado esperado |
|---|---|---|
| Assinar (CA confiável) | `1`, informar `documento.txt` | Cria `assinaturas_digitais/documento/` com a assinatura A, as chaves e os certificados |
| Caso A | `2` | Assinatura válida, cadeia confiável: DOCUMENTO ACEITO |
| Caso B | `3`, confirmar com `S`, digitar o novo conteúdo e `FIM`; depois `2` | Assinatura inválida: DOCUMENTO ADULTERADO - REJEITADO |
| Caso C | `4`; depois `2` | Assinatura válida, cadeia não confiável: ASSINATURA NAO CONFIAVEL - REJEITADA |

### Conferência independente com OpenSSL

Execute os comandos dentro de `assinaturas_digitais/documento/`:

```bash
openssl x509 -in signatario_A.pem -pubkey -noout > pub_A.pem
openssl dgst -sha256 -verify pub_A.pem -signature assinatura_A.bin documento.txt
openssl verify -CAfile ca_confiavel.pem signatario_A.pem
openssl verify -CAfile ca_confiavel.pem signatario_C.pem   # esperado: error 20
openssl x509 -in ca_confiavel.pem -noout -fingerprint -sha256
```

## Artefatos gerados

- **Parte I:** o criptograma (`.aes`), o nonce, a chave AES e o criptograma adulterado.
- **Parte II:**
  - as assinaturas `assinatura_A.bin` e `assinatura_C.bin`;
  - os certificados `ca_confiavel.pem`, `ca_desconhecida.pem`, `signatario_A.pem` e `signatario_C.pem`, que contêm as chaves públicas usadas na verificação;
  - o documento alterado e a cópia original (`.save.txt`).

As chaves privadas (`.key`) só existem para este ambiente de teste e não devem ser distribuídas em um cenário real.

## Referências das ferramentas

- cryptography (PyCA): https://cryptography.io/
- OpenSSL 1.1.1: https://www.openssl.org/docs/man1.1.1/
- NIST SP 800-38D (GCM), RFC 8017 (PKCS #1), RFC 5280 (X.509)
