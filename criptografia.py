
import os
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ==========================================
# CONFIGURAÇÕES
# ==========================================

PASTA_PRINCIPAL = Path("arquivos_criptografados")


# ==========================================
# FUNÇÃO PARA LOCALIZAR OS ARQUIVOS
# ==========================================

def obter_caminhos(pasta):

    nome = pasta.name

    return {
        "criptografado": pasta / f"{nome}.aes",
        "adulterado": pasta / f"{nome}_adulterado.aes",
        "nonce": pasta / f"nonce_{nome}.bin",
        "chave": pasta / f"chave_{nome}.key",
        "nome": pasta / "nome_original.txt"
    }


# ==========================================
# SELECIONAR DOCUMENTO CRIPTOGRAFADO
# ==========================================

def selecionar_documento():

    if not PASTA_PRINCIPAL.exists():
        print("\nNenhum documento criptografado encontrado.")
        return None

    # Localiza todas as pastas de documentos
    pastas = [
        p for p in PASTA_PRINCIPAL.iterdir()
        if p.is_dir()
    ]

    if not pastas:
        print("\nNenhum documento criptografado encontrado.")
        return None

    print("\nDOCUMENTOS DISPONÍVEIS:")

    for i, pasta in enumerate(pastas, 1):
        print(f"{i} - {pasta.name}")

    try:
        escolha = int(input("\nSelecione um documento: "))

        if escolha < 1 or escolha > len(pastas):
            print("\nOpção inválida.")
            return None

        return pastas[escolha - 1]

    except ValueError:
        print("\nDigite um número válido.")
        return None


# ==========================================
# 1 - SELECIONAR E CRIPTOGRAFAR DOCUMENTO
# ==========================================

def selecionar_e_criptografar():

    caminho = input("\nInforme o caminho do documento: ").strip()
    caminho = caminho.strip('"')

    arquivo = Path(caminho)

    if not arquivo.is_file():
        print("\nArquivo não encontrado.")
        return

    # Lê o documento original
    documento = arquivo.read_bytes()

    # Obtém o nome sem extensão
    nome = arquivo.stem

    # Cria uma pasta exclusiva para o documento
    pasta = PASTA_PRINCIPAL / nome
    
    # Evita sobrescrever documentos anteriores
    if pasta.exists():
        print("\nJá existe uma pasta para esse documento.")
        print("Renomeie o documento ou escolha outro arquivo.")
        return

    pasta.mkdir(parents=True)

    caminhos = obter_caminhos(pasta)

    # Gera chave e nonce
    chave = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)

    # Criptografa
    aesgcm = AESGCM(chave)
    dados_criptografados = aesgcm.encrypt(
        nonce, documento, None
    )

    # Salva os arquivos
    caminhos["criptografado"].write_bytes(dados_criptografados)
    caminhos["nonce"].write_bytes(nonce)
    caminhos["chave"].write_bytes(chave)
    caminhos["nome"].write_text(arquivo.name, encoding="utf-8")

    print("\nDocumento criptografado com sucesso!")
    print(f"Documento original: {arquivo.name}")
    print(f"Pasta criada: {pasta}")

    print("\nArquivos gerados:")
    for item in pasta.iterdir():
        print(f"- {item.name}")


# ==========================================
# CARREGAR ARQUIVOS
# ==========================================

def carregar_arquivos():

    pasta = selecionar_documento()

    if pasta is None:
        return None

    caminhos = obter_caminhos(pasta)

    dados = caminhos["criptografado"].read_bytes()
    nonce = caminhos["nonce"].read_bytes()
    chave = caminhos["chave"].read_bytes()
    nome = caminhos["nome"].read_text(encoding="utf-8")

    return dados, nonce, chave, nome, caminhos


# ==========================================
# 2 - DESCRIPTOGRAFAR COM A CHAVE CORRETA
# ==========================================

def descriptografar_correto():

    resultado = carregar_arquivos()

    if resultado is None:
        return

    dados, nonce, chave, nome, caminhos = resultado

    # Verifica se o documento já foi recuperado
    arquivo_recuperado = Path(f"recuperado_{nome}")

    if arquivo_recuperado.exists():
        print("\nAVISO: Este documento já foi descriptografado!")
        print(f"Arquivo recuperado: {arquivo_recuperado}")
        return

    aesgcm = AESGCM(chave)

    documento = aesgcm.decrypt(nonce, dados, None)

    # Recupera o documento original
    arquivo_recuperado.write_bytes(documento)

    print("\nSucesso! Documento recuperado.")
    print(f"Arquivo gerado: {arquivo_recuperado}")


# ==========================================
# 3 - TESTAR DESCRIPTOGRAFIA COM CHAVE INCORRETA
# ==========================================

def testar_chave_incorreta():

    resultado = carregar_arquivos()

    if resultado is None:
        return

    dados, nonce, chave, nome, caminhos = resultado

    # Gera uma chave diferente
    chave_incorreta = AESGCM.generate_key(bit_length=256)

    aesgcm = AESGCM(chave_incorreta)

    try:
        aesgcm.decrypt(nonce, dados, None)

        print("\nDocumento descriptografado.")

    except Exception:
        print("\nFalha! Chave incorreta detectada.")


# ==========================================
# 4 - ALTERAR DOCUMENTO CRIPTOGRAFADO
# ==========================================

def alterar_documento():

    pasta = selecionar_documento()

    if pasta is None:
        return

    caminhos = obter_caminhos(pasta)

    dados = caminhos["criptografado"].read_bytes()

    if not dados:
        print("\nDocumento criptografado vazio.")
        return

    # Cria uma cópia dos dados
    dados_adulterados = bytearray(dados)

    # Modifica um bit
    dados_adulterados[0] ^= 1

    # Salva separadamente
    caminhos["adulterado"].write_bytes(dados_adulterados)

    print("\nDocumento alterado com sucesso!")
    print(f"Arquivo gerado: {caminhos['adulterado']}")


# ==========================================
# 5 - TESTAR DETECÇÃO DE ALTERAÇÃO
# ==========================================

def testar_adulteracao():

    pasta = selecionar_documento()

    if pasta is None:
        return

    caminhos = obter_caminhos(pasta)

    nonce = caminhos["nonce"].read_bytes()
    chave = caminhos["chave"].read_bytes()

    # Verifica se existe documento adulterado
    if caminhos["adulterado"].exists():

        dados = caminhos["adulterado"].read_bytes()

        print("\nVerificando documento adulterado...")

    else:

        dados = caminhos["criptografado"].read_bytes()

        print("\nVerificando documento original...")

    aesgcm = AESGCM(chave)

    try:

        aesgcm.decrypt(nonce, dados, None)

        print("\nSucesso! Integridade confirmada.")
        print("Nenhuma adulteração detectada.")

    except Exception:

        print("\nFalha! Adulteração detectada pelo AES-GCM.")


# ==========================================
# MENU PRINCIPAL
# ==========================================

def menu():

    while True:

        print("\n========================================")
        print("       SISTEMA DE CRIPTOGRAFIA AES-GCM")
        print("========================================")

        print("\n1 - Selecionar e criptografar documento")
        print("2 - Descriptografar com a chave correta")
        print("3 - Testar chave incorreta")
        print("4 - Alterar documento criptografado")
        print("5 - Testar detecção de alteração")
        print("0 - Sair")

        opcao = input("\nEscolha uma opção: ")

        try:

            if opcao == "1":
                selecionar_e_criptografar()

            elif opcao == "2":
                descriptografar_correto()

            elif opcao == "3":
                testar_chave_incorreta()

            elif opcao == "4":
                alterar_documento()

            elif opcao == "5":
                testar_adulteracao()

            elif opcao == "0":
                print("\nEncerrando o programa...")
                break

            else:
                print("\nOpção inválida.")

        except FileNotFoundError:
            print("\nArquivos necessários não encontrados.")

        except Exception as erro:
            print(f"\nErro durante a execução: {erro}")


# ==========================================
# INICIALIZAÇÃO
# ==========================================

if __name__ == "__main__":
    menu()