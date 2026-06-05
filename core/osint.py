import socket
import requests
import json

R = "\033[1;31m"
G = "\033[1;32m"
Y = "\033[1;33m"
C = "\033[1;36m"
W = "\033[0m"

def executar_osint(alvo, output=None):
    print(f"\n{C}[*] Iniciando OSINT em: {alvo}{W}\n")
    resultados = []

    # Remove http/https se houver
    dominio = alvo.replace("https://", "").replace("http://", "").split("/")[0]

    # 1. Resolve IP
    try:
        ip = socket.gethostbyname(dominio)
        linha = f"{G}[+] IP Resolvido:{W} {ip}"
        print(linha)
        resultados.append(linha)
    except Exception as e:
        linha = f"{R}[-] Não foi possível resolver IP: {e}{W}"
        print(linha)
        resultados.append(linha)
        ip = None

    # 2. Geolocalização
    if ip:
        try:
            r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            geo = r.json()
            if geo.get("status") == "success":
                infos = [
                    f"{G}[+] País:{W} {geo.get('country')}",
                    f"{G}[+] Região:{W} {geo.get('regionName')}",
                    f"{G}[+] Cidade:{W} {geo.get('city')}",
                    f"{G}[+] ISP:{W} {geo.get('isp')}",
                    f"{G}[+] Org:{W} {geo.get('org')}",
                    f"{G}[+] AS:{W} {geo.get('as')}",
                ]
                for i in infos:
                    print(i)
                    resultados.append(i)
        except Exception as e:
            print(f"{R}[-] Erro na geolocalização: {e}{W}")

    # 3. WHOIS via API
    try:
        r = requests.get(f"https://api.whois.vu/?q={dominio}", timeout=5)
        if r.status_code == 200:
            dados = r.text[:500]
            linha = f"{G}[+] WHOIS:{W}\n{dados}"
            print(linha)
            resultados.append(linha)
    except Exception as e:
        print(f"{Y}[!] WHOIS indisponível: {e}{W}")

    # 4. Cabeçalhos HTTP
    try:
        r = requests.get(f"http://{dominio}", timeout=5)
        print(f"\n{C}[*] Headers HTTP:{W}")
        for k, v in r.headers.items():
            linha = f"{G}[+]{W} {k}: {v}"
            print(linha)
            resultados.append(linha)
    except Exception as e:
        print(f"{Y}[!] Headers indisponíveis: {e}{W}")

    # Salva output
    if output:
        with open(output, "w") as f:
            f.write("\n".join(resultados))
        print(f"\n{G}[+] Resultado salvo em: {output}{W}")

    print(f"\n{G}[✓] OSINT finalizado.{W}\n")
