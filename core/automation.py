import os
import subprocess
import shutil
from datetime import datetime

R = "\033[1;31m"
G = "\033[1;32m"
Y = "\033[1;33m"
C = "\033[1;36m"
W = "\033[0m"

# ─────────────────────────────────────────
def gerar_relatorio_html(alvo, dados):
    os.makedirs(os.path.expanduser("~/TEWEE/resultados"), exist_ok=True)
    nome = f"relatorio_{alvo.replace('.','_')}_{datetime.now().strftime('%Y%m%d_%H%M')}.html"
    caminho = os.path.expanduser(f"~/TEWEE/resultados/{nome}")
    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>TEWEE - Relatorio {alvo}</title>
<style>
body{{background:#0d0d0d;color:#00ff00;font-family:monospace;padding:20px}}
h1{{color:#ff0000}}h2{{color:#00ffff}}
.ok{{color:#00ff00}}.warn{{color:#ffff00}}.danger{{color:#ff0000}}
pre{{background:#111;padding:10px;border-left:3px solid #00ff00}}
</style></head><body>
<h1>T.E.W.E.E - Relatorio</h1>
<p>Alvo: <b>{alvo}</b> | Data: {datetime.now().strftime('%d/%m/%Y %H:%M')}</p>
<h2>Resultado</h2>
<pre>{dados}</pre>
</body></html>"""
    with open(caminho, "w") as f:
        f.write(html)
    print(f"{G}[+] Relatorio HTML salvo:{W} {caminho}")
    return caminho

# ─────────────────────────────────────────
def fazer_backup():
    print(f"\n{C}[*] Fazendo backup do TEWEE:{W}")
    origem = os.path.expanduser("~/TEWEE")
    destino = os.path.expanduser(f"~/TEWEE_backup_{datetime.now().strftime('%Y%m%d_%H%M')}")
    try:
        shutil.copytree(origem, destino,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".git"))
        print(f"{G}[+] Backup criado em:{W} {destino}")
    except Exception as e:
        print(f"{R}[-] Erro no backup: {e}{W}")

# ─────────────────────────────────────────
def executar_auto(tarefa):
    print(f"\n{C}[*] Automacao: {tarefa}{W}\n")

    if tarefa == "update":
        print(f"{Y}[*] Atualizando pacotes do Termux...{W}")
        os.system("pkg update -y && pkg upgrade -y")
        print(f"\n{Y}[*] Atualizando dependencias Python...{W}")
        os.system("pip install --upgrade requests dnspython")
        print(f"{G}[✓] Update concluido.{W}")

    elif tarefa == "limpeza":
        print(f"{Y}[*] Limpando cache...{W}")
        os.system("pkg clean")
        os.system("pip cache purge 2>/dev/null")
        # Limpa pycache
        for root, dirs, files in os.walk(os.path.expanduser("~/TEWEE")):
            for d in dirs:
                if d == "__pycache__":
                    shutil.rmtree(os.path.join(root, d))
                    print(f"{G}[+] Removido:{W} {os.path.join(root, d)}")
        print(f"{G}[✓] Limpeza concluida.{W}")

    elif tarefa == "info":
        print(f"{Y}[*] Informacoes do sistema:{W}")
        cmds = {
            "Usuario": "whoami",
            "Hostname": "hostname",
            "IP Local": "ip route get 1 2>/dev/null | awk '{print $7}' | head -1",
            "Python": "python3 --version",
            "Git": "git --version",
            "Storage": "df -h /data 2>/dev/null | tail -1",
            "Memoria": "free -h 2>/dev/null | grep Mem",
        }
        for nome, cmd in cmds.items():
            resultado = subprocess.getoutput(cmd)
            print(f"{G}[+] {nome}:{W} {resultado}")

    elif tarefa == "backup":
        fazer_backup()

    elif tarefa == "relatorio":
        print(f"{Y}[*] Use --alvo com --osint ou --vulns e adicione -o resultado.txt{W}")
        print(f"{Y}    Depois rode: python3 tewee.py --auto relatorio{W}")

    print()
