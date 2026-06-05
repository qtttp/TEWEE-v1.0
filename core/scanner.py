import socket
import threading

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

def testar_porta(ip, porta, timeout=1):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        resultado = s.connect_ex((ip, porta))
        s.close()
        if resultado == 0:
            servico = PORTAS_COMUNS.get(porta, "Desconhecido")
            with lock:
                abertas.append(porta)
                print(f"{G}[+] Porta {porta}/tcp ABERTA{W} — {servico}")
    except:
        pass

def executar_scan(alvo, tipo, output=None):
    global abertas
    abertas = []
    print(f"\n{C}[*] Iniciando scan ({tipo}) em: {alvo}{W}\n")

    dominio = alvo.replace("https://", "").replace("http://", "").split("/")[0]
    try:
        ip = socket.gethostbyname(dominio)
        print(f"{Y}[*] IP: {ip}{W}\n")
    except:
        print(f"{R}[ERRO] Não foi possível resolver {alvo}{W}")
        return

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

    print(f"\n{G}[✓] Scan finalizado. {len(abertas)} porta(s) abertas.{W}\n")

    if output and abertas:
        with open(output, "w") as f:
            f.write(f"Scan em {alvo}\nPortas abertas: {abertas}\n")
        print(f"{G}[+] Salvo em: {output}{W}")
