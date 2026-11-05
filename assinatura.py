import subprocess
from pathlib import Path
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding


# ==========================================
# CONFIGURACOES
# ==========================================

PASTA_PRINCIPAL = Path("assinaturas_digitais")


# ==========================================
# OBTER CAMINHOS DOS ARQUIVOS
# ==========================================

def obter_caminhos(pasta):

    nome_original = (pasta / "nome_original.txt").read_text(
        encoding="utf-8"
    )

    arquivo = Path(nome_original)
    nome = arquivo.stem
    extensao = arquivo.suffix

    return {
        "documento": pasta / f"{nome}{extensao}",
        "backup": pasta / f"{nome}.save{extensao}",

        "assinatura_A": pasta / "assinatura_A.bin",
        "assinatura_C": pasta / "assinatura_C.bin",

        "chave_ca_confiavel": pasta / "ca_confiavel.key",
        "ca_confiavel": pasta / "ca_confiavel.pem",

        "chave_ca_desconhecida": pasta / "ca_desconhecida.key",
        "ca_desconhecida": pasta / "ca_desconhecida.pem",

        "chave_A": pasta / "signatario_A.key",
        "cert_A": pasta / "signatario_A.pem",

        "chave_C": pasta / "signatario_C.key",
        "cert_C": pasta / "signatario_C.pem",

        "nome": pasta / "nome_original.txt"
    }


# ==========================================
# SELECIONAR DOCUMENTO
# ==========================================

def selecionar_documento():

    if not PASTA_PRINCIPAL.exists():
        print("\nNenhum documento assinado encontrado.")
        return None

    pastas = [
        p for p in PASTA_PRINCIPAL.iterdir()
        if p.is_dir() and (p / "nome_original.txt").exists()
    ]

    if not pastas:
        print("\nNenhum documento assinado encontrado.")
        return None

    print("\nDOCUMENTOS DISPONIVEIS:")

    for i, pasta in enumerate(pastas, 1):
        print(f"{i} - {pasta.name}")

    try:
        escolha = int(input("\nSelecione um documento: "))

        if escolha < 1 or escolha > len(pastas):
            print("\nOpcao invalida.")
            return None

        return pastas[escolha - 1]

    except ValueError:
        print("\nDigite um numero valido.")
        return None


# ==========================================
# 1. GERACAO DAS AUTORIDADES CERTIFICADORAS
# ==========================================

def criar_ca(nome):

    chave = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    sujeito = emissor = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, nome)
    ])

    certificado = (
        x509.CertificateBuilder()
        .subject_name(sujeito)
        .issuer_name(emissor)
        .public_key(chave.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        )
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=1),
            critical=True
        )
        .sign(chave, hashes.SHA256())
    )

    return chave, certificado


# ==========================================
# 2. EMISSAO DE CERTIFICADOS
# ==========================================

def emitir_certificado(nome, chave_ca, certificado_ca):

    chave = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    sujeito = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, nome)
    ])

    certificado = (
        x509.CertificateBuilder()
        .subject_name(sujeito)
        .issuer_name(certificado_ca.subject)
        .public_key(chave.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=180)
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        .sign(chave_ca, hashes.SHA256())
    )

    return chave, certificado


# ==========================================
# 3. SALVAR CHAVES E CERTIFICADOS
# ==========================================

def salvar_chave(chave, caminho):

    caminho.write_bytes(
        chave.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    )


def salvar_certificado(certificado, caminho):

    caminho.write_bytes(
        certificado.public_bytes(serialization.Encoding.PEM)
    )


# ==========================================
# 4. CARREGAR CHAVES E CERTIFICADOS
# ==========================================

def carregar_chave(caminho):

    return serialization.load_pem_private_key(
        caminho.read_bytes(),
        password=None
    )


def carregar_certificado(caminho):

    return x509.load_pem_x509_certificate(caminho.read_bytes())


# ==========================================
# 5. ASSINAR DOCUMENTO
# ==========================================

def assinar(conteudo, chave):

    return chave.sign(
        conteudo,
        padding.PKCS1v15(),
        hashes.SHA256()
    )


# ==========================================
# 6. VERIFICAR ASSINATURA DIGITAL
# ==========================================

def verificar_assinatura_criptografica(conteudo, assinatura, certificado):

    try:
        certificado.public_key().verify(
            assinatura,
            conteudo,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True

    except Exception:
        return False


# ==========================================
# 7. VALIDAR CADEIA DE CERTIFICADOS
# ==========================================

def validar_cadeia(certificado, ca_confiavel):

    resultado = subprocess.run(
        [
            "openssl",
            "verify",
            "-CAfile",
            str(ca_confiavel),
            str(certificado)
        ],
        capture_output=True,
        text=True
    )

    detalhe = resultado.stdout.strip() or resultado.stderr.strip()

    return resultado.returncode == 0, detalhe


# ==========================================
# 8. SELECIONAR E ASSINAR DOCUMENTO
# ==========================================

def selecionar_e_assinar():

    caminho = input("\nInforme o caminho do documento: ").strip()
    caminho = caminho.strip('"')

    arquivo = Path(caminho)

    if not arquivo.is_file():
        print("\nArquivo nao encontrado.")
        return

    nome = arquivo.stem
    # A pasta principal so e criada depois que um documento valido e escolhido.
    PASTA_PRINCIPAL.mkdir(parents=True, exist_ok=True)
    pasta = PASTA_PRINCIPAL / nome

    if pasta.exists():
        print("\nJa existe uma pasta para esse documento.")
        print("Renomeie o arquivo ou escolha outro documento.")
        return

    pasta.mkdir(parents=True)

    # Salva o nome original para identificar os arquivos.
    (pasta / "nome_original.txt").write_text(
        arquivo.name,
        encoding="utf-8"
    )

    caminhos = obter_caminhos(pasta)

    documento = arquivo.read_bytes()

    # Salva o documento e sua copia de seguranca.
    caminhos["documento"].write_bytes(documento)
    caminhos["backup"].write_bytes(documento)

    # --------------------------------------
    # GERAR AS AUTORIDADES CERTIFICADORAS
    # --------------------------------------

    chave_ca_confiavel, ca_confiavel = criar_ca("CA_XYZW")

    # --------------------------------------
    # EMITIR OS CERTIFICADOS
    # --------------------------------------

    chave_A, cert_A = emitir_certificado(
        "Signatario XYZW",
        chave_ca_confiavel,
        ca_confiavel
    )

    # --------------------------------------
    # SALVAR CHAVES E CERTIFICADOS
    # --------------------------------------

    salvar_chave(chave_ca_confiavel, caminhos["chave_ca_confiavel"])
    salvar_certificado(ca_confiavel, caminhos["ca_confiavel"])

    salvar_chave(chave_A, caminhos["chave_A"])
    salvar_certificado(cert_A, caminhos["cert_A"])

    # --------------------------------------
    # GERAR AS ASSINATURAS
    # --------------------------------------

    assinatura_A = assinar(documento, chave_A)
    caminhos["assinatura_A"].write_bytes(assinatura_A)

    print("\nDocumento assinado com sucesso!")
    print(f"\nPasta criada: {pasta}")

    print("\nArquivos gerados:")
    for item in sorted(pasta.iterdir()):
        print(f"- {item.name}")


# ==========================================
# 9. ALTERAR O PROPRIO DOCUMENTO
# ==========================================

def alterar_documento():

    pasta = selecionar_documento()

    if pasta is None:
        return

    caminhos = obter_caminhos(pasta)

    if not caminhos["documento"].exists():
        print("\nDocumento nao encontrado.")
        return

    print("\nATENCAO: esta operacao vai sobrescrever o arquivo atual.")
    print("Uma copia de seguranca (.save.txt) sera mantida.")

    confirmacao = input("Deseja continuar? (S/N): ").strip().upper()

    if confirmacao != "S":
        print("\nAlteracao cancelada.")
        return

    print("\nDigite o novo conteudo do documento.")
    print("Para finalizar, escreva FIM em uma linha separada.")
    print("-----------------------------------------------")

    linhas = []

    while True:
        linha = input()
        if linha.strip().upper() == "FIM":
            break
        linhas.append(linha)

    novo_conteudo = "\n".join(linhas).encode("utf-8")

    if not novo_conteudo:
        print("\nO documento nao pode ficar vazio. Alteracao cancelada.")
        return

    # Sobrescreve o proprio documento; o backup permanece intacto.
    caminhos["documento"].write_bytes(novo_conteudo)

    print("\nDocumento alterado com sucesso!")
    print(f"Arquivo modificado: {caminhos['documento']}")
    print("A assinatura original nao foi modificada.")


# ==========================================
# 10. ASSINAR POR AUTORIDADE DESCONHECIDA
# ==========================================

def assinar_orgao_desconhecido():

    pasta = selecionar_documento()

    if pasta is None:
        return

    caminhos = obter_caminhos(pasta)

    if caminhos["assinatura_C"].exists():
        print("\nEste documento ja possui uma assinatura da autoridade desconhecida.")
        return

    # A assinatura C e feita sobre o backup original para que o teste
    # da autoridade seja independente de uma eventual adulteracao.
    documento_original = caminhos["backup"].read_bytes()

    chave_ca_desconhecida, ca_desconhecida = criar_ca("CA_DESCONHECIDA")
    chave_C, cert_C = emitir_certificado(
        "Signatario Externo",
        chave_ca_desconhecida,
        ca_desconhecida
    )

    salvar_chave(chave_ca_desconhecida, caminhos["chave_ca_desconhecida"])
    salvar_certificado(ca_desconhecida, caminhos["ca_desconhecida"])
    salvar_chave(chave_C, caminhos["chave_C"])
    salvar_certificado(cert_C, caminhos["cert_C"])

    assinatura_C = assinar(documento_original, chave_C)
    caminhos["assinatura_C"].write_bytes(assinatura_C)

    print("\nDocumento assinado pela autoridade desconhecida com sucesso!")
    print("O cenario C agora esta habilitado para este documento.")


# ==========================================
# 11. VERIFICAR OS TRES CENARIOS JUNTOS
# ==========================================

def verificar_cenario():

    pasta = selecionar_documento()

    if pasta is None:
        return

    caminhos = obter_caminhos(pasta)

    documento_atual = caminhos["documento"].read_bytes()
    documento_original = caminhos["backup"].read_bytes()

    # --------------------------------------
    # CENARIO A - ASSINATURA CONFIAVEL
    # Verifica o arquivo que esta atualmente salvo.
    # --------------------------------------

    assinatura_A = caminhos["assinatura_A"].read_bytes()
    certificado_A = carregar_certificado(caminhos["cert_A"])

    assinatura_A_valida = verificar_assinatura_criptografica(
        documento_atual,
        assinatura_A,
        certificado_A
    )

    cadeia_A, detalhe_A = validar_cadeia(
        caminhos["cert_A"],
        caminhos["ca_confiavel"]
    )

    # --------------------------------------
    # CENARIO B - DETECCAO DE ADULTERACAO
    # Compara o arquivo atual com o backup original e tambem
    # verifica a assinatura A contra o arquivo atual.
    # --------------------------------------

    alteracao_detectada = documento_atual != documento_original
    assinatura_B_valida = verificar_assinatura_criptografica(
        documento_atual,
        assinatura_A,
        certificado_A
    )

    # --------------------------------------
    # CENARIO C - AUTORIDADE DESCONHECIDA
    # Usa o backup original para isolar o teste da autoridade.
    # Assim, a assinatura C continua matematicamente valida,
    # mesmo que o arquivo atual tenha sido alterado no cenario B.
    # --------------------------------------

    c_disponivel = caminhos["assinatura_C"].exists()

    if c_disponivel:
        assinatura_C = caminhos["assinatura_C"].read_bytes()
        certificado_C = carregar_certificado(caminhos["cert_C"])

        assinatura_C_valida = verificar_assinatura_criptografica(
            documento_original,
            assinatura_C,
            certificado_C
        )

        cadeia_C, detalhe_C = validar_cadeia(
            caminhos["cert_C"],
            caminhos["ca_confiavel"]
        )

    # --------------------------------------
    # RESULTADOS
    # --------------------------------------

    print("\n========== RESULTADOS DAS VERIFICACOES ==========")

    print("\nCENARIO A - DOCUMENTO E AUTORIDADE CONFIAVEL")
    print("Assinatura valida:", assinatura_A_valida)
    print("Cadeia confiavel:", cadeia_A)
    print("Detalhe:", detalhe_A)
    print("Decisao:", "DOCUMENTO ACEITO" if assinatura_A_valida and cadeia_A else "DOCUMENTO REJEITADO")

    print("\nCENARIO B - DETECCAO DE ADULTERACAO")
    print("Alteracao detectada:", alteracao_detectada)
    print("Assinatura valida no arquivo atual:", assinatura_B_valida)
    print("Decisao:", "DOCUMENTO ADULTERADO - REJEITADO" if alteracao_detectada or not assinatura_B_valida else "NENHUMA ALTERACAO DETECTADA")

    print("\nCENARIO C - AUTORIDADE DESCONHECIDA")
    if c_disponivel:
        print("Assinatura valida:", assinatura_C_valida)
        print("Cadeia confiavel:", cadeia_C)
        print("Detalhe:", detalhe_C)
        print("Decisao:", "DOCUMENTO ACEITO" if assinatura_C_valida and cadeia_C else "ASSINATURA NAO CONFIAVEL - REJEITADA")
    else:
        print("Nao executado: o documento ainda nao foi assinado por uma autoridade desconhecida.")
        print("Utilize a opcao 4 para habilitar este cenario.")

    print("\n========== RESULTADO FINAL ==========")

    documento_aceitavel = assinatura_A_valida and cadeia_A and not alteracao_detectada

    if documento_aceitavel:
        print("Documento atual: integro e assinado por autoridade confiavel.")
    elif alteracao_detectada:
        print("Documento atual: adulterado ou com assinatura invalida.")
    elif not assinatura_A_valida:
        print("Documento atual: assinatura invalida.")
    else:
        print("Documento atual: cadeia de certificados nao confiavel.")

    if alteracao_detectada:
        print("Adulteracao: alteracao detectada em relacao ao backup original.")
    else:
        print("Adulteracao: nenhuma alteracao detectada.")

    if c_disponivel:
        if assinatura_C_valida and not cadeia_C:
            print("Autoridade externa: assinatura valida, mas sem cadeia confiavel.")
        elif assinatura_C_valida and cadeia_C:
            print("Autoridade externa: assinatura valida e cadeia confiavel.")
        else:
            print("Autoridade externa: assinatura invalida.")
    else:
        print("Autoridade externa: cenario nao executado.")

    # A decisao considera a assinatura principal, a integridade do arquivo
    # e, quando o cenario C foi habilitado, a confiabilidade da autoridade externa.
    decisao_aceitar = documento_aceitavel and (
        not c_disponivel or (assinatura_C_valida and cadeia_C)
    )

    print("Decisao final:", "ACEITAR" if decisao_aceitar else "REJEITAR")
    print("===============================================")


# ==========================================
# MENU PRINCIPAL
# ==========================================

def menu():

    while True:

        print("\n========================================")
        print("       SISTEMA DE ASSINATURA DIGITAL")
        print("========================================")

        print("\n1 - Selecionar e assinar documento (autoridade XYZW)")
        print("2 - Verificar os tres cenarios")
        print("3 - Alterar o proprio documento")
        print("4 - Assinar por autoridade desconhecida (cenario C)")
        print("0 - Sair")

        opcao = input("\nEscolha uma opcao: ").strip()

        try:

            if opcao == "1":
                selecionar_e_assinar()

            elif opcao == "2":
                verificar_cenario()

            elif opcao == "3":
                alterar_documento()

            elif opcao == "4":
                assinar_orgao_desconhecido()

            elif opcao == "0":
                print("\nEncerrando o programa...")
                break

            else:
                print("\nOpcao invalida.")

        except FileNotFoundError:
            print("\nArquivos necessarios nao encontrados.")
            print("Verifique se o documento foi assinado corretamente.")

        except subprocess.SubprocessError as erro:
            print(f"\nErro ao executar o OpenSSL: {erro}")

        except Exception as erro:
            print(f"\nErro durante a execucao: {erro}")


# ==========================================
# INICIALIZACAO
# ==========================================

if __name__ == "__main__":
    menu()
