#!/usr/bin/env bash
# =====================================================================
#  XYZW TECNOLOGIA - Roteiro automatizado de testes
#  Trabalho 01 - Criptografia Aplicada
#
#  Este script reproduz, de forma automatica, as interacoes com os
#  programas criptografia.py e assinatura.py que correspondem aos
#  casos de teste pedidos na questao:
#
#    PARTE I  - Protecao e integridade com AES-GCM (itens 1 a 5)
#    PARTE II - Assinaturas digitais e certificados (casos A, B e C)
#
#  Os dois programas sao interativos (menus com input()). O script
#  alimenta a entrada padrao (stdin) com as mesmas opcoes que um
#  usuario digitaria, guarda a saida de cada interacao como evidencia
#  e, em seguida, confere o resultado esperado. Sempre que possivel a
#  conclusao do Python e confirmada de forma independente com OpenSSL.
#
#  COMO EXECUTAR (Windows, pelo Git Bash, na pasta do repositorio):
#      bash executar_testes.sh
#
#  REQUISITOS: Python 3 com o pacote "cryptography" (pip install
#  cryptography) e OpenSSL no PATH (o Git for Windows ja traz um).
#
#  SAIDA: tudo e gerado em ./execucao_testes/ (recriada a cada
#  execucao). Os logs de cada passo ficam em ./execucao_testes/evidencias/
# =====================================================================

set -u

# ---------------------------------------------------------------------
# Configuracao
# ---------------------------------------------------------------------

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TRABALHO="$REPO/execucao_testes"
EVID="$TRABALHO/evidencias"
DOC="documento.txt"

# Garante UTF-8 na troca de texto com o Python (acentos nos menus e no documento)
export PYTHONIOENCODING=utf-8
export PYTHONUTF8=1

if [ -t 1 ]; then
    VERDE=$'\033[1;32m'; VERMELHO=$'\033[1;31m'; AMARELO=$'\033[1;33m'
    AZUL=$'\033[1;36m'; NEGRITO=$'\033[1m'; RESET=$'\033[0m'
else
    VERDE=""; VERMELHO=""; AMARELO=""; AZUL=""; NEGRITO=""; RESET=""
fi

TOTAL=0
APROVADOS=0
FALHAS=()

# ---------------------------------------------------------------------
# Funcoes auxiliares de apresentacao
# ---------------------------------------------------------------------

titulo() {
    echo
    echo "${AZUL}=====================================================================${RESET}"
    echo "${AZUL} $1${RESET}"
    echo "${AZUL}=====================================================================${RESET}"
}

passo() {
    echo
    echo "${NEGRITO}>>> $1${RESET}"
}

# Explica o que esta sendo verificado no passo
objetivo() {
    echo "${AMARELO}    O que se verifica: $1${RESET}"
}

info() {
    echo "    $1"
}

# Mostra um bloco de saida recuado, para separar da narracao
mostrar() {
    sed 's/^/      | /'
}

# Registra o resultado de uma verificacao
# uso: verificar "descricao" <comando de teste...>
verificar() {
    local descricao="$1"; shift
    TOTAL=$((TOTAL + 1))
    if "$@"; then
        APROVADOS=$((APROVADOS + 1))
        echo "    ${VERDE}[OK]${RESET}    $descricao"
    else
        FALHAS+=("$descricao")
        echo "    ${VERMELHO}[FALHA]${RESET} $descricao"
    fi
}

# Testa se um texto aparece em um arquivo de log
contem() {
    grep -qF -- "$2" "$1"
}

# Executa um dos programas Python alimentando o menu pelo stdin.
# uso: menu <script.py> <arquivo_de_log> <entradas separadas por \n>
menu() {
    local script="$1" log="$2" entradas="$3"
    info "Entradas enviadas ao menu: $(printf '%s' "$entradas" | tr '\n' ' ' | cut -c1-90)"
    printf '%b' "$entradas" | "$PY" "$REPO/$script" > "$log" 2>&1
    # Remove o eco repetido do menu para deixar a evidencia legivel
    tr -d '\r' < "$log" | grep -vE '^(=+|       SISTEMA|[0-9] - |0 - Sair|$)' | mostrar
}

tamanho() {
    wc -c < "$1" | tr -d ' '
}

sha256() {
    sha256sum "$1" | cut -d' ' -f1
}

# ---------------------------------------------------------------------
# Verificacao do ambiente
# ---------------------------------------------------------------------

titulo "PREPARACAO DO AMBIENTE"

passo "Localizando o interpretador Python com o pacote cryptography"
PY=""
for candidato in python python3 py; do
    if command -v "$candidato" >/dev/null 2>&1 &&
       "$candidato" -c "import cryptography" >/dev/null 2>&1; then
        PY="$candidato"
        break
    fi
done
if [ -z "$PY" ]; then
    echo "${VERMELHO}Python com o pacote 'cryptography' nao encontrado.${RESET}"
    echo "Instale com: pip install cryptography"
    exit 1
fi
info "Python: $("$PY" --version 2>&1)  |  cryptography $("$PY" -c 'import cryptography; print(cryptography.__version__)')"

if ! command -v openssl >/dev/null 2>&1; then
    echo "${VERMELHO}OpenSSL nao encontrado no PATH.${RESET}"
    exit 1
fi
info "OpenSSL: $(openssl version)"

passo "Criando uma area de testes limpa em execucao_testes/"
objetivo "os programas gravam em pastas relativas ao diretorio atual e se recusam a
                        sobrescrever resultados antigos; por isso cada execucao comeca do zero."
rm -rf "$TRABALHO"
mkdir -p "$EVID"
cp "$REPO/$DOC" "$TRABALHO/$DOC"
cd "$TRABALHO" || exit 1
info "Diretorio de trabalho: $TRABALHO"


# =====================================================================
#  PARTE I - PROTECAO E INTEGRIDADE DE DOCUMENTOS (AES-GCM)
# =====================================================================

titulo "PARTE I - PROTECAO E INTEGRIDADE DE DOCUMENTOS (AES-GCM)"

# ---------------------------------------------------------------------
passo "I.1 - Documento comercial ficticio em .txt"
objetivo "o documento de entrada existe e registramos seu hash SHA-256 de referencia."
head -n 6 "$DOC" | tr -d '\r' | mostrar
info "..."
HASH_ORIGINAL="$(sha256 "$DOC")"
info "Tamanho: $(tamanho "$DOC") bytes"
info "SHA-256: $HASH_ORIGINAL"
verificar "Documento ficticio $DOC disponivel" test -s "$DOC"

# ---------------------------------------------------------------------
passo "I.2 - Criptografar o documento com AES-GCM (menu opcao 1)"
objetivo "o programa gera chave de 256 bits e nonce de 96 bits aleatorios e produz um
                        criptograma que nao revela o texto original."
menu criptografia.py "$EVID/I2_criptografar.log" "1\n$DOC\n0\n"

PASTA_AES="arquivos_criptografados/documento"
AES="$PASTA_AES/documento.aes"
CHAVE="$PASTA_AES/chave_documento.key"
NONCE="$PASTA_AES/nonce_documento.bin"

verificar "Programa informou sucesso na criptografia" contem "$EVID/I2_criptografar.log" "Documento criptografado com sucesso"
verificar "Criptograma .aes foi gerado" test -s "$AES"
verificar "Chave AES tem 32 bytes (256 bits)" test "$(tamanho "$CHAVE")" -eq 32
verificar "Nonce tem 12 bytes (96 bits, recomendado para GCM)" test "$(tamanho "$NONCE")" -eq 12

TAM_DOC=$(tamanho "$DOC"); TAM_AES=$(tamanho "$AES")
info "Tamanho do texto claro: $TAM_DOC bytes | criptograma: $TAM_AES bytes"
info "A diferenca de $((TAM_AES - TAM_DOC)) bytes e a tag de autenticacao do GCM (128 bits)."
verificar "Criptograma = texto claro + 16 bytes de tag" test "$TAM_AES" -eq $((TAM_DOC + 16))

info "Primeiros bytes do criptograma (hexadecimal):"
od -An -tx1 -N32 "$AES" | mostrar
verificar "Texto 'XYZW TECNOLOGIA' NAO aparece no criptograma (confidencialidade)" \
    bash -c "test -s '$AES' && ! grep -qa 'XYZW TECNOLOGIA' '$AES'"

# ---------------------------------------------------------------------
passo "I.4a - Controle: verificar a integridade do criptograma ainda intacto (menu opcao 5)"
objetivo "antes de qualquer alteracao, a verificacao da tag GCM precisa passar; isso
                        prova que a falha vista mais adiante e causada pela adulteracao."
menu criptografia.py "$EVID/I4a_integridade_original.log" "5\n1\n0\n"
verificar "Criptograma original passou na verificacao de integridade" \
    contem "$EVID/I4a_integridade_original.log" "Integridade confirmada"

# ---------------------------------------------------------------------
passo "I.3 - Descriptografar com a chave correta (menu opcao 2)"
objetivo "com a chave e o nonce corretos o documento recuperado e identico, byte a byte,
                        ao original."
menu criptografia.py "$EVID/I3_descriptografar.log" "2\n1\n0\n"
RECUPERADO="recuperado_$DOC"
verificar "Programa informou que o documento foi recuperado" contem "$EVID/I3_descriptografar.log" "Documento recuperado"
verificar "Arquivo $RECUPERADO foi gerado" test -s "$RECUPERADO"
info "SHA-256 original:    $HASH_ORIGINAL"
info "SHA-256 recuperado:  $(sha256 "$RECUPERADO")"
verificar "Documento recuperado e identico ao original (cmp)" cmp -s "$DOC" "$RECUPERADO"

# ---------------------------------------------------------------------
passo "I.4b - Descriptografar com uma chave incorreta (menu opcao 3)"
objetivo "uma chave AES diferente, gerada ao acaso, nao consegue abrir o documento; a
                        tag nao confere e o GCM rejeita a operacao sem liberar texto."
menu criptografia.py "$EVID/I4b_chave_incorreta.log" "3\n1\n0\n"
verificar "Descriptografia com chave incorreta foi recusada" \
    contem "$EVID/I4b_chave_incorreta.log" "Falha! Chave incorreta detectada"
verificar "Nenhum texto foi liberado com a chave incorreta" \
    bash -c "test -s '$EVID/I4b_chave_incorreta.log' && ! grep -q 'Documento descriptografado' '$EVID/I4b_chave_incorreta.log'"

# ---------------------------------------------------------------------
passo "I.4c - Alterar o conteudo criptografado (menu opcao 4)"
objetivo "o programa inverte 1 unico bit do criptograma e salva uma copia adulterada."
menu criptografia.py "$EVID/I4c_alterar.log" "4\n1\n0\n"
ADULTERADO="$PASTA_AES/documento_adulterado.aes"
verificar "Copia adulterada do criptograma foi gerada" test -s "$ADULTERADO"
info "Bytes diferentes entre original e adulterado (posicao, valor octal original, adulterado):"
cmp -l "$AES" "$ADULTERADO" | mostrar
verificar "Exatamente 1 byte difere entre os dois criptogramas" \
    test "$(cmp -l "$AES" "$ADULTERADO" | wc -l)" -eq 1

# ---------------------------------------------------------------------
passo "I.4d - Descriptografar o criptograma adulterado (menu opcao 5)"
objetivo "mesmo com a chave correta, a alteracao de 1 bit invalida a tag GCM e a
                        descriptografia e rejeitada (integridade e autenticidade)."
menu criptografia.py "$EVID/I4d_integridade_adulterado.log" "5\n1\n0\n"
verificar "Programa analisou o criptograma adulterado" \
    contem "$EVID/I4d_integridade_adulterado.log" "Verificando documento adulterado"
verificar "Adulteracao foi detectada pelo AES-GCM" \
    contem "$EVID/I4d_integridade_adulterado.log" "Falha! Adulteração detectada pelo AES-GCM"

# ---------------------------------------------------------------------
passo "I.5 - Propriedades de seguranca garantidas"
cat <<'EOF' | mostrar
Confidencialidade: o texto claro nao aparece no criptograma (I.2) e so e
  recuperado com a chave correta (I.3); com outra chave nada e revelado (I.4b).
Integridade: a alteracao de um unico bit faz a verificacao da tag GCM falhar
  e o conteudo e rejeitado por inteiro (I.4c e I.4d).
Autenticidade da origem: apenas quem possui a chave simetrica consegue gerar
  uma tag valida; a tag liga o criptograma a essa chave (AEAD).
Limites: GCM nao oferece nao-repudio (a chave e compartilhada); a seguranca
  depende de nunca reutilizar o mesmo nonce com a mesma chave e de proteger
  o arquivo .key, que neste experimento fica ao lado do criptograma apenas
  para fins didaticos.
EOF


# =====================================================================
#  PARTE II - ASSINATURAS DIGITAIS E CERTIFICADOS
# =====================================================================

titulo "PARTE II - ASSINATURAS DIGITAIS E CERTIFICADOS"

PASTA_ASS="assinaturas_digitais/documento"
DOC_ASS="$PASTA_ASS/documento.txt"
BACKUP="$PASTA_ASS/documento.save.txt"
CA_OK="$PASTA_ASS/ca_confiavel.pem"
CA_DESC="$PASTA_ASS/ca_desconhecida.pem"
CERT_A="$PASTA_ASS/signatario_A.pem"
CERT_C="$PASTA_ASS/signatario_C.pem"
SIG_A="$PASTA_ASS/assinatura_A.bin"
SIG_C="$PASTA_ASS/assinatura_C.bin"

# Mostra emissor, sujeito e validade de um certificado
detalhar_certificado() {
    openssl x509 -in "$1" -noout -subject -issuer -startdate -enddate | mostrar
}

# Verifica uma assinatura RSA PKCS#1 v1.5 + SHA-256 de forma independente com OpenSSL
# uso: openssl_assinatura <certificado> <assinatura> <documento> <log>
openssl_assinatura() {
    openssl x509 -in "$1" -pubkey -noout > "$EVID/chave_publica.tmp.pem"
    openssl dgst -sha256 -verify "$EVID/chave_publica.tmp.pem" -signature "$2" "$3" > "$4" 2>&1
    local rc=$?
    rm -f "$EVID/chave_publica.tmp.pem"
    mostrar < "$4"
    return $rc
}

# Valida a cadeia de um certificado contra uma CA com OpenSSL
# uso: openssl_cadeia <ca> <certificado> <log>
openssl_cadeia() {
    openssl verify -CAfile "$1" "$2" > "$3" 2>&1
    local rc=$?
    mostrar < "$3"
    return $rc
}

# ---------------------------------------------------------------------
passo "II.0 - Assinar o documento original com a CA confiavel (menu opcao 1)"
objetivo "o programa cria a CA_XYZW (autoassinada, ancora de confianca), emite o
                        certificado do 'Signatario XYZW' e assina o documento com RSA-2048,
                        PKCS#1 v1.5 e SHA-256."
menu assinatura.py "$EVID/II0_assinar.log" "1\n$DOC\n0\n"
verificar "Programa informou que o documento foi assinado" contem "$EVID/II0_assinar.log" "Documento assinado com sucesso"
verificar "Assinatura A, certificado A e CA confiavel foram gerados" \
    bash -c "test -s '$SIG_A' && test -s '$CERT_A' && test -s '$CA_OK'"
info "Tamanho da assinatura A: $(tamanho "$SIG_A") bytes (RSA-2048 = 256 bytes)"
info "Certificado do signatario A:"
detalhar_certificado "$CERT_A"

# ---------------------------------------------------------------------
titulo "CASO A - Documento original, assinatura correta, certificado confiavel"

passo "A.1 - Verificacao pelo programa (menu opcao 2)"
objetivo "assinatura valida + cadeia confiavel => documento aceito."
menu assinatura.py "$EVID/A_verificar.log" "2\n1\n0\n"
verificar "Assinatura A verificada como valida" contem "$EVID/A_verificar.log" "Assinatura valida: True"
verificar "Cadeia do certificado A validada contra a CA_XYZW" contem "$EVID/A_verificar.log" "Cadeia confiavel: True"
verificar "Decisao do caso A: DOCUMENTO ACEITO" contem "$EVID/A_verificar.log" "Decisao: DOCUMENTO ACEITO"
verificar "Nenhuma adulteracao apontada" contem "$EVID/A_verificar.log" "Alteracao detectada: False"

passo "A.2 - Evidencia independente: assinatura conferida com OpenSSL"
objetivo "a chave publica do certificado A valida a assinatura sobre o documento atual."
verificar "OpenSSL: assinatura A sobre o documento -> Verified OK" \
    openssl_assinatura "$CERT_A" "$SIG_A" "$DOC_ASS" "$EVID/A_openssl_assinatura.log"

passo "A.3 - Evidencia independente: cadeia de certificacao com OpenSSL"
objetivo "o certificado A foi emitido pela CA_XYZW, que e a ancora de confianca."
verificar "OpenSSL: certificado A confiavel pela CA_XYZW -> OK" \
    openssl_cadeia "$CA_OK" "$CERT_A" "$EVID/A_openssl_cadeia.log"

info "${NEGRITO}Decisao A: ACEITAR.${RESET} Assinatura matematicamente valida, documento integro e"
info "certificado emitido por uma CA confiavel."

# ---------------------------------------------------------------------
titulo "CASO B - Documento alterado apos a assinatura"

passo "B.1 - Alterar o documento ja assinado (menu opcao 3)"
objetivo "simular um atacante que muda o VALOR TOTAL de R\$ 15.000,00 para R\$ 150.000,00
                        sem alterar a assinatura (o programa guarda uma copia .save.txt)."
CONTEUDO_ALTERADO="$(tr -d '\r' < "$DOC" | sed 's/R\$ 15\.000,00/R$ 150.000,00/')"
menu assinatura.py "$EVID/B_alterar.log" "3\n1\nS\n${CONTEUDO_ALTERADO//\\/\\\\}\nFIM\n0\n"
verificar "Programa informou que o documento foi alterado" contem "$EVID/B_alterar.log" "Documento alterado com sucesso"
info "Diferenca entre a copia original (.save.txt) e o documento atual:"
# (ignora a diferenca de quebra de linha Windows/Unix, que nao e a adulteracao em si)
diff <(tr -d '\r' < "$BACKUP") <(cat "$DOC_ASS"; echo) | mostrar
info "SHA-256 original: $(sha256 "$BACKUP")"
info "SHA-256 atual:    $(sha256 "$DOC_ASS")"
verificar "Conteudo do documento realmente mudou" \
    bash -c "test -s '$BACKUP' && test -s '$DOC_ASS' && ! cmp -s '$BACKUP' '$DOC_ASS'"
verificar "Assinatura A nao foi modificada pela alteracao" test -s "$SIG_A"

passo "B.2 - Verificacao pelo programa (menu opcao 2)"
objetivo "o hash do documento alterado nao confere com o hash assinado => assinatura
                        invalida, apesar de a cadeia continuar confiavel."
menu assinatura.py "$EVID/B_verificar.log" "2\n1\n0\n"
verificar "Alteracao detectada em relacao ao original" contem "$EVID/B_verificar.log" "Alteracao detectada: True"
verificar "Assinatura invalida para o arquivo atual" contem "$EVID/B_verificar.log" "Assinatura valida no arquivo atual: False"
verificar "Cadeia do certificado A continua confiavel" contem "$EVID/B_verificar.log" "Cadeia confiavel: True"
verificar "Decisao do caso B: DOCUMENTO ADULTERADO - REJEITADO" contem "$EVID/B_verificar.log" "DOCUMENTO ADULTERADO - REJEITADO"

passo "B.3 - Evidencia independente: assinatura conferida com OpenSSL"
objetivo "a mesma assinatura A, que valia para o original, falha no documento alterado."
openssl_assinatura "$CERT_A" "$SIG_A" "$DOC_ASS" "$EVID/B_openssl_assinatura.log"
verificar "OpenSSL: assinatura A sobre o documento ALTERADO -> Verification Failure" \
    contem "$EVID/B_openssl_assinatura.log" "Verification Failure"
verificar "OpenSSL: assinatura A sobre a copia ORIGINAL -> Verified OK (controle)" \
    openssl_assinatura "$CERT_A" "$SIG_A" "$BACKUP" "$EVID/B_openssl_controle.log"

info "${NEGRITO}Decisao B: REJEITAR.${RESET} O certificado e confiavel, mas a assinatura nao"
info "corresponde ao conteudo atual: o documento foi adulterado depois de assinado."

# ---------------------------------------------------------------------
titulo "CASO C - Assinatura valida, mas certificado de CA nao confiavel"

passo "C.1 - Assinar com uma autoridade desconhecida (menu opcao 4)"
objetivo "o programa cria a CA_DESCONHECIDA, emite o certificado 'Signatario Externo' e
                        assina a copia original do documento (sem adulteracao)."
menu assinatura.py "$EVID/C_assinar.log" "4\n1\n0\n"
verificar "Programa informou que a assinatura C foi criada" contem "$EVID/C_assinar.log" "assinado pela autoridade desconhecida com sucesso"
verificar "Assinatura C, certificado C e CA desconhecida foram gerados" \
    bash -c "test -s '$SIG_C' && test -s '$CERT_C' && test -s '$CA_DESC'"
info "Certificado do signatario C:"
detalhar_certificado "$CERT_C"

passo "C.2 - Verificacao pelo programa (menu opcao 2)"
objetivo "assinatura matematicamente valida, porem a cadeia nao chega a uma CA confiavel
                        => documento rejeitado."
menu assinatura.py "$EVID/C_verificar.log" "2\n1\n0\n"
# Isola o bloco do cenario C dentro do relatorio do programa
sed -n '/CENARIO C/,/RESULTADO FINAL/p' "$EVID/C_verificar.log" > "$EVID/C_bloco.log"
verificar "Assinatura C verificada como matematicamente valida" contem "$EVID/C_bloco.log" "Assinatura valida: True"
verificar "Cadeia do certificado C NAO e confiavel" contem "$EVID/C_bloco.log" "Cadeia confiavel: False"
verificar "Decisao do caso C: ASSINATURA NAO CONFIAVEL - REJEITADA" contem "$EVID/C_bloco.log" "ASSINATURA NAO CONFIAVEL - REJEITADA"
verificar "Resultado final do programa: REJEITAR" contem "$EVID/C_verificar.log" "Decisao final: REJEITAR"

passo "C.3 - Evidencia independente: assinatura conferida com OpenSSL"
objetivo "a chave publica do certificado C valida a assinatura C sobre o original."
verificar "OpenSSL: assinatura C sobre o documento original -> Verified OK" \
    openssl_assinatura "$CERT_C" "$SIG_C" "$BACKUP" "$EVID/C_openssl_assinatura.log"

passo "C.4 - Evidencia independente: cadeia de certificacao com OpenSSL"
objetivo "contra a ancora confiavel (CA_XYZW) a cadeia falha; ela so fecharia se a
                        CA_DESCONHECIDA fosse aceita como confiavel, o que nao e o caso."
openssl_cadeia "$CA_OK" "$CERT_C" "$EVID/C_openssl_cadeia.log"
verificar "OpenSSL: certificado C contra a CA_XYZW -> falha de cadeia" \
    contem "$EVID/C_openssl_cadeia.log" "verification failed"
verificar "Erro de cadeia e 'unable to get local issuer certificate' (emissor desconhecido)" \
    contem "$EVID/C_openssl_cadeia.log" "unable to get local issuer certificate"
verificar "OpenSSL: certificado C contra a propria CA_DESCONHECIDA -> OK (so ela o reconhece)" \
    openssl_cadeia "$CA_DESC" "$CERT_C" "$EVID/C_openssl_cadeia_desconhecida.log"

info "${NEGRITO}Decisao C: REJEITAR.${RESET} A matematica da assinatura confere, mas a identidade"
info "do signatario nao e garantida: o certificado foi emitido por uma CA fora da"
info "lista de confianca da XYZW. Assinatura valida sem cadeia confiavel nao prova autoria."


# =====================================================================
#  RESUMO
# =====================================================================

titulo "RESUMO DOS TESTES"

printf '    %-8s %-22s %-20s %s\n' "Caso" "Assinatura" "Cadeia" "Decisao"
printf '    %-8s %-22s %-20s %s\n' "A" "valida" "confiavel" "ACEITAR"
printf '    %-8s %-22s %-20s %s\n' "B" "INVALIDA (alterado)" "confiavel" "REJEITAR"
printf '    %-8s %-22s %-20s %s\n' "C" "valida" "NAO confiavel" "REJEITAR"
echo
info "Evidencias salvas em: $EVID"
info "Artefatos gerados em: $TRABALHO/arquivos_criptografados e $TRABALHO/assinaturas_digitais"
echo

if [ "${#FALHAS[@]}" -eq 0 ]; then
    echo "    ${VERDE}${APROVADOS}/${TOTAL} verificacoes aprovadas.${RESET}"
    exit 0
else
    echo "    ${VERMELHO}${APROVADOS}/${TOTAL} verificacoes aprovadas. Falharam:${RESET}"
    for f in "${FALHAS[@]}"; do echo "      - $f"; done
    exit 1
fi
