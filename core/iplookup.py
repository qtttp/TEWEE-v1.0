import socket
import requests
import subprocess

R = "\033[1;31m"
G = "\033[1;32m"
Y = "\033[1;33m"
C = "\033[1;36m"
M = "\033[1;35m"
W = "\033[0m"

LUPA = f"""
{Y}
    .---.
   /     \\
  | () () |
   \\  ^  /
    '---'
      |
      |
{W}"""

def lookup_ip(alvo, output=None):
    print(LUPA)
    print(f"{C}[*] IP Lookup: {alvo}{W}\n")
    resultados = []

    # Modo: meu proprio IP
    if alvo.lower() in ["meu", "me", "self", "eu"]:
        print(f"{Y}[*] Seu IP local:{W}")
        try:
            ip_local = subprocess.getoutput(
                "ip route get 1 2>/dev/null | awk '{print $7}' | head -1"
            )
            if not ip_local:
                ip_local = socket.gethostbyname(socket.gethostname())
            linha = f"{G}[+] IP Local:{W} {ip_local}"
            print(linha); resultados.append(linha)
        except:
            print(f"{Y}[-] IP local nao encontrado{W}")

        print(f"\n{Y}[*] Seu IP publico:{W}")
        try:
            ip_pub = requests.get("https://api.ipify.org", timeout=5).text.strip()
            linha = f"{G}[+] IP Publico:{W} {ip_pub}"
            print(linha); resultados.append(linha)
            alvo = ip_pub  # continua com geolocalizacao
        except:
            try:
                ip_pub = requests.get("https://ifconfig.me", timeout=5).text.strip()
                linha = f"{G}[+] IP Publico:{W} {ip_pub}"
                print(linha); resultados.append(linha)
                alvo = ip_pub
            except:
                print(f"{R}[-] Nao foi possivel obter IP publico{W}")
                return

    # Resolve dominio para IP
    ip = alvo
    if not alvo.replace(".","").isdigit():
        try:
            ip = socket.gethostbyname(alvo)
            linha = f"{G}[+] Dominio resolvido:{W} {alvo} -> {ip}"
            print(linha); resultados.append(linha)
        except:
            print(f"{R}[ERRO] Nao foi possivel resolver: {alvo}{W}")
            return

    # Geolocalizacao detalhada
    print(f"\n{C}[*] Informacoes do IP: {ip}{W}")
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=66846719", timeout=5)
        geo = r.json()
        if geo.get("status") == "success":
            campos = [
                ("IP",          "query"),
                ("Pais",        "country"),
                ("Codigo",      "countryCode"),
                ("Regiao",      "regionName"),
                ("Cidade",      "city"),
                ("CEP/ZIP",     "zip"),
                ("Latitude",    "lat"),
                ("Longitude",   "lon"),
                ("Fuso",        "timezone"),
                ("ISP",         "isp"),
                ("Organizacao", "org"),
                ("AS",          "as"),
                ("ASName",      "asname"),
                ("Proxy/VPN",   "proxy"),
                ("Hosting",     "hosting"),
                ("Mobile",      "mobile"),
            ]
            for nome, chave in campos:
                valor = geo.get(chave)
                if valor not in [None, "", False]:
                    if chave in ["proxy","hosting","mobile"] and valor:
                        cor = R
                    else:
                        cor = G
                    linha = f"{cor}[+] {nome}:{W} {valor}"
                    print(linha); resultados.append(linha)
        else:
            print(f"{Y}[-] IP privado ou nao encontrado{W}")
    except Exception as e:
        print(f"{R}[-] Erro na geolocalizacao: {e}{W}")

    # Verifica se e proxy/VPN conhecida
    print(f"\n{C}[*] Verificando reputacao:{W}")
    try:
        r2 = requests.get(f"https://proxycheck.io/v2/{ip}?vpn=1&asn=1", timeout=5)
        data = r2.json()
        if ip in data:
            info = data[ip]
            vpn = info.get("vpn", "no")
            proxy = info.get("proxy", "no")
            tipo = info.get("type", "unknown")
            if vpn == "yes" or proxy == "yes":
                print(f"{R}[!] VPN/Proxy DETECTADO:{W} tipo={tipo}")
            else:
                print(f"{G}[ok] IP nao parece ser VPN/Proxy{W}")
    except:
        print(f"{Y}[-] Verificacao de reputacao indisponivel{W}")

    # Traceroute rapido
    print(f"\n{C}[*] Rota ate o IP:{W}")
    try:
        resultado = subprocess.getoutput(f"traceroute -m 5 {ip} 2>/dev/null || tracepath -m 5 {ip}")
        for linha in resultado.split("\n")[1:6]:
            if linha.strip():
                print(f"{G}[+]{W} {linha.strip()}")
    except:
        print(f"{Y}[-] Traceroute indisponivel{W}")

    if output:
        with open(output, "w") as f:
            f.write(f"IP Lookup: {alvo}\n" + "\n".join(resultados))
        print(f"\n{G}[+] Salvo em: {output}{W}")

    print(f"\n{G}[✓] IP Lookup finalizado.{W}\n")
