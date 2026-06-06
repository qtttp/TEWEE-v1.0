import socket
import requests
import re
import subprocess

R = "\033[1;31m"
G = "\033[1;32m"
Y = "\033[1;33m"
C = "\033[1;36m"
M = "\033[1;35m"
W = "\033[0m"

def secao(titulo):
    print(f"\n{C}{'='*45}")
    print(f"  {titulo}")
    print(f"{'='*45}{W}")

def linha(label, valor, cor=G):
    print(f"{cor}[+] {label}:{W} {valor}")

# ─────────────────────────────────────────
def investigar_whois(dominio):
    secao("WHOIS / REGISTRO DO DOMINIO")
    try:
        import whois
        w = whois.whois(dominio)
        linha("Dominio",     dominio)
        linha("Registrador", w.registrar or "--")
        linha("Criado em",   str(w.creation_date).split("[")[0].strip())
        linha("Expira em",   str(w.expiration_date).split("[")[0].strip())
        if w.name_servers:
            for ns in (w.name_servers if isinstance(w.name_servers, list) else [w.name_servers]):
                linha("Nameserver", ns)
    except ImportError:
        print(f"{Y}[!] Instale: pip install python-whois{W}")
    except Exception as e:
        print(f"{Y}[-] WHOIS indisponivel: {e}{W}")

# ─────────────────────────────────────────
def investigar_ip(dominio):
    secao("IP E GEOLOCALIZACAO")
    try:
        ip = socket.gethostbyname(dominio)
        linha("IP Resolvido", ip)

        r = requests.get(f"http://ip-api.com/json/{ip}?fields=66846719", timeout=5)
        geo = r.json()
        if geo.get("status") == "success":
            linha("Pais",      geo.get("country","--"))
            linha("Cidade",    geo.get("city","--"))
            linha("ISP",       geo.get("isp","--"))
            linha("Org",       geo.get("org","--"))
            linha("AS",        geo.get("as","--"))
            if geo.get("proxy"):
                linha("Proxy/VPN", "DETECTADO", R)
            if geo.get("hosting"):
                linha("Hosting", "SIM (pode ser Cloudflare/CDN)", Y)
        return ip
    except Exception as e:
        print(f"{R}[-] Erro: {e}{W}")
        return None

# ─────────────────────────────────────────
def investigar_headers(dominio):
    secao("HEADERS HTTP")
    try:
        r = requests.get(f"https://{dominio}",
            headers={"Cache-Control":"no-cache"}, timeout=5)
        campos = ["Server","X-Powered-By","CF-RAY","Via",
                  "X-Frame-Options","Strict-Transport-Security",
                  "Content-Type","Set-Cookie"]
        for h in campos:
            if h in r.headers:
                val = r.headers[h][:80]
                cor = R if h == "CF-RAY" else G
                linha(h, val, cor)
        if "CF-RAY" in r.headers:
            print(f"{R}[!] Cloudflare detectado — IP real pode estar oculto{W}")
    except Exception as e:
        print(f"{Y}[-] Erro headers: {e}{W}")

# ─────────────────────────────────────────
def investigar_subdominios(dominio):
    secao("SUBDOMINIOS")
    subs = ["www","mail","ftp","admin","api","dev","test",
            "direct","cpanel","vpn","server","smtp","ns1","ns2",
            "staging","shop","blog","app","cdn","portal"]
    encontrados = []
    for sub in subs:
        try:
            ip = socket.gethostbyname(f"{sub}.{dominio}")
            linha(f"{sub}.{dominio}", ip)
            encontrados.append((sub, ip))
        except:
            pass
    if not encontrados:
        print(f"{Y}[-] Nenhum subdominio encontrado{W}")
    return encontrados

# ─────────────────────────────────────────
def investigar_hackertarget(dominio):
    secao("HISTORICO DE SUBDOMINIOS (HackerTarget)")
    try:
        r = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={dominio}",
            timeout=8)
        if r.status_code == 200 and "error" not in r.text.lower():
            for linha_txt in r.text.strip().split("\n"):
                if linha_txt:
                    partes = linha_txt.split(",")
                    if len(partes) == 2:
                        linha(partes[0], partes[1])
        else:
            print(f"{Y}[-] Sem resultados ou limite atingido{W}")
    except Exception as e:
        print(f"{Y}[-] Erro: {e}{W}")

# ─────────────────────────────────────────
def investigar_emails_loja(url):
    secao("EMAILS E CONTATOS NA PAGINA")
    try:
        r = requests.get(url, timeout=8,
            headers={"User-Agent":"Mozilla/5.0"})
        emails = set(re.findall(
            r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
            r.text))
        phones = set(re.findall(
            r'(\(?\d{2}\)?\s?\d{4,5}[-\s]?\d{4})', r.text))
        cnpjs = set(re.findall(
            r'\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}', r.text))

        if emails:
            for e in emails:
                linha("Email", e)
        else:
            print(f"{Y}[-] Nenhum email encontrado{W}")

        if phones:
            for p in phones:
                linha("Telefone", p)

        if cnpjs:
            for c in cnpjs:
                linha("CNPJ", c, R)
        else:
            print(f"{Y}[-] Nenhum CNPJ encontrado{W}")
    except Exception as e:
        print(f"{Y}[-] Erro: {e}{W}")

# ─────────────────────────────────────────
def investigar_perfis(username):
    secao(f"PERFIS SOCIAIS: @{username}")
    redes = {
        "GitHub":    f"https://github.com/{username}",
        "Twitter":   f"https://twitter.com/{username}",
        "Instagram": f"https://instagram.com/{username}",
        "Reddit":    f"https://reddit.com/user/{username}",
        "TikTok":    f"https://tiktok.com/@{username}",
        "Telegram":  f"https://t.me/{username}",
        "YouTube":   f"https://youtube.com/@{username}",
        "Linktree":  f"https://linktr.ee/{username}",
    }
    for rede, url in redes.items():
        try:
            resp = requests.get(url, timeout=4,
                headers={"User-Agent":"Mozilla/5.0"})
            if resp.status_code == 200:
                linha(f"{rede}", url, G)
            else:
                print(f"{Y}[-] {rede}: {resp.status_code}{W}")
        except:
            print(f"{Y}[-] {rede}: erro{W}")

# ─────────────────────────────────────────
def investigar_gateway(url):
    secao("GATEWAY DE PAGAMENTO")
    try:
        r = requests.get(url, timeout=8,
            headers={"User-Agent":"Mozilla/5.0"})
        gateways = {
            "Mercado Pago": r"mercadopago",
            "Yampi":        r"yampi",
            "Appmax":       r"appmax",
            "Pagar.me":     r"pagar\.me",
            "iugu":         r"iugu",
            "Cartpanda":    r"cartpanda",
            "Hotmart":      r"hotmart",
            "Eduzz":        r"eduzz",
            "Monetizze":    r"monetizze",
            "Kiwify":       r"kiwify",
            "Stripe":       r"stripe",
            "PayPal":       r"paypal",
        }
        encontrado = False
        for nome, padrao in gateways.items():
            if re.search(padrao, r.text, re.IGNORECASE):
                linha(f"Gateway detectado", nome, R)
                encontrado = True
        if not encontrado:
            print(f"{Y}[-] Nenhum gateway detectado no HTML{W}")
            print(f"{Y}    Pode estar carregando via script dinamico{W}")
    except Exception as e:
        print(f"{Y}[-] Erro: {e}{W}")

# ─────────────────────────────────────────
def executar_investiga(alvo, output=None):
    print(f"\n{M}[★] INVESTIGACAO COMPLETA: {alvo}{W}")
    resultados = []

    dominio = alvo.replace("https://","").replace("http://","").split("/")[0]
    username = dominio.split(".")[0]
    url = f"https://{dominio}"

    investigar_whois(dominio)
    investigar_ip(dominio)
    investigar_headers(dominio)
    investigar_subdominios(dominio)
    investigar_hackertarget(dominio)
    investigar_emails_loja(url)
    investigar_gateway(url)
    investigar_perfis(username)

    print(f"\n{G}{'='*45}")
    print(f"  [✓] INVESTIGACAO FINALIZADA")
    print(f"{'='*45}{W}\n")

    if output:
        with open(output, "w") as f:
            f.write(f"Investigacao: {alvo}\n")
        print(f"{G}[+] Salvo em: {output}{W}")

# ─────────────────────────────────────────
def investigar_telefone(numero):
    secao(f"BUSCA POR TELEFONE: {numero}")

    # Limpa o numero
    num = re.sub(r'\D', '', numero)

    # Identifica DDD
    ddds = {
        "11":"Sao Paulo/SP","12":"Sao Jose dos Campos/SP",
        "13":"Santos/SP","14":"Bauru/SP","15":"Sorocaba/SP",
        "16":"Ribeirao Preto/SP","17":"Sao Jose do Rio Preto/SP",
        "18":"Presidente Prudente/SP","19":"Campinas/SP",
        "21":"Rio de Janeiro/RJ","22":"Campos/RJ","24":"Volta Redonda/RJ",
        "27":"Vitoria/ES","28":"Cachoeiro/ES",
        "31":"Belo Horizonte/MG","32":"Juiz de Fora/MG",
        "33":"Governador Valadares/MG","34":"Uberlandia/MG",
        "35":"Varginha/MG","37":"Divinopolis/MG","38":"Montes Claros/MG",
        "41":"Curitiba/PR","42":"Ponta Grossa/PR","43":"Londrina/PR",
        "44":"Maringa/PR","45":"Foz do Iguacu/PR","46":"Francisco Beltrao/PR",
        "47":"Joinville/SC","48":"Florianopolis/SC","49":"Chapeco/SC",
        "51":"Porto Alegre/RS","53":"Pelotas/RS","54":"Caxias do Sul/RS",
        "55":"Santa Maria/RS",
        "61":"Brasilia/DF","62":"Goiania/GO","63":"Palmas/TO",
        "64":"Rio Verde/GO","65":"Cuiaba/MT","66":"Rondonopolis/MT",
        "67":"Campo Grande/MS","68":"Rio Branco/AC","69":"Porto Velho/RO",
        "71":"Salvador/BA","73":"Ilheus/BA","74":"Juazeiro/BA",
        "75":"Feira de Santana/BA","77":"Vitoria da Conquista/BA",
        "79":"Aracaju/SE","81":"Recife/PE","82":"Maceio/AL",
        "83":"Joao Pessoa/PB","84":"Natal/RN","85":"Fortaleza/CE",
        "86":"Teresina/PI","87":"Caruaru/PE","88":"Juazeiro do Norte/CE",
        "89":"Picos/PI","91":"Belem/PA","92":"Manaus/AM",
        "93":"Santarem/PA","94":"Maraba/PA","95":"Boa Vista/RR",
        "96":"Macapa/AP","97":"Coari/AM","98":"Sao Luis/MA","99":"Imperatriz/MA",
    }

    if len(num) >= 10:
        ddd = num[:2]
        resto = num[2:]
        regiao = ddds.get(ddd, "Desconhecido")
        linha("DDD", ddd)
        linha("Regiao", regiao)
        linha("Numero", f"({ddd}) {resto}")

        # Tipo (fixo ou celular)
        if len(resto) == 9 and resto[0] == "9":
            linha("Tipo", "Celular")
        elif len(resto) == 8:
            linha("Tipo", "Fixo")
        else:
            linha("Tipo", "Indefinido")

    # Busca no WhatsApp (verifica se tem conta)
    print(f"\n{Y}[*] Links de verificacao:{W}")
    print(f"{G}[+] WhatsApp:{W} https://wa.me/55{num}")
    print(f"{G}[+] Telegram:{W} https://t.me/+55{num}")

    # Busca publica via TrueCaller-like
    print(f"\n{Y}[*] Busca publica:{W}")
    buscas = [
        ("Google",    f"https://www.google.com/search?q=%2255{num}"),
        ("NumeroInfo", f"https://www.numeroinfo.com.br/{num}"),
        ("TelefoneSP", f"https://www.telefonesp.com.br/{num}"),
    ]
    for nome, url in buscas:
        print(f"{G}[+] {nome}:{W} {url}")


def executar_telefone(numero, output=None):
    investigar_telefone(numero)
    if output:
        with open(output, "w") as f:
            f.write(f"Telefone: {numero}\n")
        print(f"\n{G}[+] Salvo em: {output}{W}")
    print(f"\n{G}[✓] Busca finalizada.{W}\n")
