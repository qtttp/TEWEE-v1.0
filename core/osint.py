import socket
import requests
import json
import re
import dns.resolver

R = "\033[1;31m"
G = "\033[1;32m"
Y = "\033[1;33m"
C = "\033[1;36m"
W = "\033[0m"

# ─────────────────────────────────────────
def executar_osint(alvo, output=None):
    print(f"\n{C}[*] Iniciando OSINT em: {alvo}{W}\n")
    resultados = []

    dominio = alvo.replace("https://", "").replace("http://", "").split("/")[0]

    # 1. Resolve IP
    try:
        ip = socket.gethostbyname(dominio)
        linha = f"{G}[+] IP Resolvido:{W} {ip}"
        print(linha); resultados.append(linha)
    except Exception as e:
        print(f"{R}[-] Nao foi possivel resolver IP: {e}{W}")
        ip = None

    # 2. Geolocalizacao
    if ip:
        try:
            r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            geo = r.json()
            if geo.get("status") == "success":
                for campo, chave in [("Pais","country"),("Regiao","regionName"),
                                     ("Cidade","city"),("ISP","isp"),
                                     ("Org","org"),("AS","as")]:
                    linha = f"{G}[+] {campo}:{W} {geo.get(chave)}"
                    print(linha); resultados.append(linha)
        except Exception as e:
            print(f"{R}[-] Erro na geolocalizacao: {e}{W}")

    # 3. DNS Records
    print(f"\n{C}[*] Registros DNS:{W}")
    for tipo in ["A", "MX", "TXT", "NS", "CNAME"]:
        try:
            respostas = dns.resolver.resolve(dominio, tipo)
            for r in respostas:
                linha = f"{G}[+] {tipo}:{W} {r.to_text()}"
                print(linha); resultados.append(linha)
        except:
            print(f"{Y}[-] {tipo}: nao encontrado{W}")

    # 4. Subdomínios comuns
    print(f"\n{C}[*] Buscando subdominios:{W}")
    subs = ["www","mail","ftp","admin","api","dev","test","staging",
            "blog","shop","vpn","remote","portal","app","cdn","ns1","ns2"]
    for sub in subs:
        try:
            ip_sub = socket.gethostbyname(f"{sub}.{dominio}")
            linha = f"{G}[+] {sub}.{dominio}{W} -> {ip_sub}"
            print(linha); resultados.append(linha)
        except:
            pass

    # 5. E-mails via scraping da pagina
    print(f"\n{C}[*] Buscando e-mails na pagina:{W}")
    try:
        r = requests.get(f"http://{dominio}", timeout=5)
        emails = set(re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", r.text))
        if emails:
            for email in emails:
                linha = f"{G}[+] Email:{W} {email}"
                print(linha); resultados.append(linha)
        else:
            print(f"{Y}[-] Nenhum e-mail encontrado na pagina{W}")
    except Exception as e:
        print(f"{Y}[-] Erro ao buscar emails: {e}{W}")

    # 6. Verifica blacklists
    print(f"\n{C}[*] Verificando blacklists:{W}")
    if ip:
        blacklists = [
            "zen.spamhaus.org", "bl.spamcop.net",
            "dnsbl.sorbs.net", "b.barracudacentral.org"
        ]
        ip_rev = ".".join(reversed(ip.split(".")))
        for bl in blacklists:
            try:
                socket.gethostbyname(f"{ip_rev}.{bl}")
                linha = f"{R}[!] BLACKLIST:{W} {bl}"
                print(linha); resultados.append(linha)
            except:
                print(f"{G}[ok]{W} Limpo em: {bl}")

    # 7. Busca perfis por username
    print(f"\n{C}[*] Buscando perfis por username ({dominio.split('.')[0]}):{W}")
    username = dominio.split(".")[0]
    redes = {
        "GitHub": f"https://github.com/{username}",
        "Twitter": f"https://twitter.com/{username}",
        "Instagram": f"https://instagram.com/{username}",
        "Reddit": f"https://reddit.com/user/{username}",
        "TikTok": f"https://tiktok.com/@{username}",
    }
    for rede, url in redes.items():
        try:
            resp = requests.get(url, timeout=4,
                headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                linha = f"{G}[+] {rede}:{W} {url}"
            else:
                linha = f"{Y}[-] {rede}:{W} nao encontrado ({resp.status_code})"
            print(linha); resultados.append(linha)
        except:
            print(f"{Y}[-] {rede}: erro de conexao{W}")

    # 8. Headers HTTP
    print(f"\n{C}[*] Headers HTTP:{W}")
    try:
        r = requests.get(f"http://{dominio}", timeout=5)
        for k, v in r.headers.items():
            linha = f"{G}[+]{W} {k}: {v}"
            print(linha); resultados.append(linha)
    except Exception as e:
        print(f"{Y}[-] Headers indisponiveis: {e}{W}")

    # Salva output
    if output:
        with open(output, "w") as f:
            f.write("\n".join(resultados))
        print(f"\n{G}[+] Resultado salvo em: {output}{W}")

    print(f"\n{G}[✓] OSINT finalizado.{W}\n")
