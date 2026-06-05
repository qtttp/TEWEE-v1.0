import socket
import threading
import subprocess
import ssl
import requests
from datetime import datetime

R = "\033[1;31m"
G = "\033[1;32m"
Y = "\033[1;33m"
C = "\033[1;36m"
W = "\033[0m"

PORTAS_COMUNS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB"
}

abertas = []
lock = threading.Lock()

# ─────────────────────────────────────────
def banner_grab(ip, porta):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip, porta))
        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = s.recv(1024).decode(errors="ignore").strip()
        s.close()
        return banner[:100] if banner else None
    except:
        return None

def testar_porta(ip, porta):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        resultado = s.connect_ex((ip, porta))
        s.close()
        if resultado == 0:
            servico = PORTAS_COMUNS.get(porta, "Desconhecido")
            banner = banner_grab(ip, porta)
            with lock:
                abertas.append(porta)
                if banner:
                    print(f"{G}[+] Porta {porta}/tcp{W} [{servico}] — Banner: {Y}{banner[:60]}{W}")
                else:
                    print(f"{G}[+] Porta {porta}/tcp{W} [{servico}]")
    except:
        pass

# ─────────────────────────────────────────
def detectar_so(ip):
    print(f"\n{C}[*] Detectando Sistema Operacional:{W}")
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip, 80))
        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        resp = s.recv(512).decode(errors="ignore")
        s.close()
        resp_lower = resp.lower()
        if "windows" in resp_lower:
            print(f"{G}[+] SO provavel:{W} Windows")
        elif "ubuntu" in resp_lower or "debian" in resp_lower:
            print(f"{G}[+] SO provavel:{W} Linux (Ubuntu/Debian)")
        elif "centos" in resp_lower or "fedora" in resp_lower:
            print(f"{G}[+] SO provavel:{W} Linux (CentOS/Fedora)")
        elif "nginx" in resp_lower:
            print(f"{G}[+] Servidor:{W} Nginx (provavelmente Linux)")
        elif "apache" in resp_lower:
            print(f"{G}[+] Servidor:{W} Apache")
        elif "iis" in resp_lower:
            print(f"{G}[+] Servidor:{W} IIS (Windows)")
        else:
            print(f"{Y}[-] SO nao identificado pelo banner{W}")
    except:
        print(f"{Y}[-] Nao foi possivel detectar SO{W}")

# ─────────────────────────────────────────
def verificar_ssl(dominio):
    print(f"\n{C}[*] Verificando certificado SSL:{W}")
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=dominio) as s:
            s.settimeout(5)
            s.connect((dominio, 443))
            cert = s.getpeercert()
            subject = dict(x[0] for x in cert["subject"])
            issuer = dict(x[0] for x in cert["issuer"])
            validade = cert["notAfter"]
            print(f"{G}[+] Dominio:{W} {subject.get('commonName')}")
            print(f"{G}[+] Emissor:{W} {issuer.get('organizationName')}")
            print(f"{G}[+] Valido ate:{W} {validade}")
            # Verifica se expirou
            exp = datetime.strptime(validade, "%b %d %H:%M:%S %Y %Z")
            if exp > datetime.utcnow():
                print(f"{G}[+] Status:{W} Certificado VALIDO")
            else:
                print(f"{R}[!] Status:{W} Certificado EXPIRADO!")
    except ssl.SSLCertVerificationError:
        print(f"{R}[!] Certificado INVALIDO ou autoassinado{W}")
    except Exception as e:
        print(f"{Y}[-] SSL indisponivel: {e}{W}")

# ─────────────────────────────────────────
def ping_traceroute(alvo):
    print(f"\n{C}[*] Ping:{W}")
    try:
        resultado = subprocess.getoutput(f"ping -c 3 {alvo}")
        linhas = resultado.split("\n")
        for l in linhas:
            if "bytes from" in l or "packet loss" in l or "min/avg" in l:
                print(f"{G}[+]{W} {l.strip()}")
    except:
        print(f"{Y}[-] Ping indisponivel{W}")

    print(f"\n{C}[*] Traceroute (primeiros 10 hops):{W}")
    try:
        resultado = subprocess.getoutput(f"traceroute -m 10 {alvo} 2>/dev/null || tracepath -m 10 {alvo}")
        for linha in resultado.split("\n")[1:11]:
            if linha.strip():
                print(f"{G}[+]{W} {linha.strip()}")
    except:
        print(f"{Y}[-] Traceroute indisponivel{W}")

# ─────────────────────────────────────────
def scanner_diretorios(alvo):
    print(f"\n{C}[*] Scanner de diretorios ocultos:{W}")
    dominio = alvo.replace("https://","").replace("http://","").split("/")[0]
    caminhos = [
        "/admin", "/administrator", "/wp-admin", "/wp-login.php",
        "/login", "/phpmyadmin", "/panel", "/dashboard", "/cpanel",
        "/.env", "/.git", "/backup", "/backup.zip", "/backup.sql",
        "/robots.txt", "/sitemap.xml", "/config.php", "/config.yml",
        "/api", "/api/v1", "/api/v2", "/swagger", "/docs",
        "/shell.php", "/cmd.php", "/test.php", "/info.php",
        "/server-status", "/server-info", "/.htaccess",
    ]
    encontrados = []
    for caminho in caminhos:
        try:
            resp = requests.get(f"http://{dominio}{caminho}",
                timeout=3, allow_redirects=False)
            if resp.status_code in [200, 301, 302, 403]:
                cor = G if resp.status_code == 200 else Y
                linha = f"{cor}[{resp.status_code}]{W} {dominio}{caminho}"
                print(linha)
                encontrados.append(linha)
        except:
            pass
    if not encontrados:
        print(f"{Y}[-] Nenhum diretorio relevante encontrado{W}")

# ─────────────────────────────────────────
def executar_scan(alvo, tipo, output=None):
    global abertas
    abertas = []
    print(f"\n{C}[*] Iniciando scan ({tipo}) em: {alvo}{W}\n")

    dominio = alvo.replace("https://","").replace("http://","").split("/")[0]
    try:
        ip = socket.gethostbyname(dominio)
        print(f"{Y}[*] IP: {ip}{W}\n")
    except:
        print(f"{R}[ERRO] Nao foi possivel resolver {alvo}{W}")
        return

    # Ping e traceroute
    ping_traceroute(dominio)

    # SSL
    verificar_ssl(dominio)

    # Detectar SO
    detectar_so(ip)

    # Scanner de portas
    print(f"\n{C}[*] Scanner de portas ({tipo}):{W}")
    if tipo == "rapido":
        portas = list(PORTAS_COMUNS.keys())
    elif tipo == "completo":
        portas = range(1, 10001)
    else:
        portas = list(PORTAS_COMUNS.keys())

    threads = []
    for porta in portas:
        t = threading.Thread(target=testar_porta, args=(ip, porta))
        threads.append(t)
        t.start()
        if len(threads) >= 100:
            for th in threads:
                th.join()
            threads = []
    for th in threads:
        th.join()

    # Scanner de diretorios
    scanner_diretorios(dominio)

    print(f"\n{G}[✓] Scan finalizado. {len(abertas)} porta(s) abertas.{W}\n")

    if output:
        with open(output, "w") as f:
            f.write(f"Scan em {alvo}\nPortas abertas: {abertas}\n")
        print(f"{G}[+] Salvo em: {output}{W}")
