import os
import subprocess

R = "\033[1;31m"
G = "\033[1;32m"
Y = "\033[1;33m"
C = "\033[1;36m"
W = "\033[0m"

def executar_auto(tarefa):
    print(f"\n{C}[*] Automação: {tarefa}{W}\n")

    if tarefa == "update":
        print(f"{Y}[*] Atualizando pacotes do Termux...{W}")
        os.system("pkg update -y && pkg upgrade -y")
        print(f"{G}[✓] Update concluído.{W}")

    elif tarefa == "limpeza":
        print(f"{Y}[*] Limpando cache...{W}")
        os.system("pkg clean")
        os.system("pip cache purge 2>/dev/null")
        print(f"{G}[✓] Limpeza concluída.{W}")

    elif tarefa == "info":
        print(f"{Y}[*] Informações do sistema:{W}")
        cmds = {
            "Usuário": "whoami",
            "Hostname": "hostname",
            "IP Local": "hostname -I",
            "Python": "python3 --version",
            "Storage": "df -h | head -5",
        }
        for nome, cmd in cmds.items():
            resultado = subprocess.getoutput(cmd)
            print(f"{G}[+] {nome}:{W} {resultado}")
    
    print()
