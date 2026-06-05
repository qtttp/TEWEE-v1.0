import requests
import socket

R = "\033[1;31m"
G = "\033[1;32m"
Y = "\033[1;33m"
C = "\033[1;36m"
W = "\033[0m"

HEADERS = {"User-Agent": "Mozilla/5.0"}

# ─────────────────────────────────────────
def testar_sqli(url):
    print(f"\n{C}[*] Testando SQL Injection:{W}")
    payloads = ["'", "''", "`", "' OR '1'='1", "' OR 1=1--", "\" OR \"1\"=\"1"]
    erros_sql = ["sql", "mysql", "syntax", "error", "warning", "ORA-", "PostgreSQL"]
    encontrado = False
    for payload in payloads:
        try:
            resp = requests.get(f"{url}?id={payload}", timeout=4,
                headers=HEADERS)
            for erro in erros_sql:
                if erro.lower() in resp.text.lower():
                    print(f"{R}[!] SQLi DETECTADO:{W} payload={payload} | erro={erro}")
                    encontrado = True
                    break
        except:
            pass
    if not encontrado:
        print(f"{G}[ok] Nenhuma vulnerabilidade SQLi obvia detectada{W}")

# ─────────────────────────────────────────
def testar_xss(url):
    print(f"\n{C}[*] Testando XSS:{W}")
    payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "'><script>alert(1)</script>",
        "<svg onload=alert(1)>",
    ]
    encontrado = False
    for payload in payloads:
        try:
            resp = requests.get(f"{url}?q={payload}", timeout=4,
                headers=HEADERS)
            if payload.lower() in resp.text.lower():
                print(f"{R}[!] XSS REFLETIDO:{W} payload={payload[:40]}")
                encontrado = True
        except:
            pass
    if not encontrado:
        print(f"{G}[ok] Nenhum XSS refletido detectado{W}")

# ─────────────────────────────────────────
def testar_arquivos_sensiveis(dominio):
    print(f"\n{C}[*] Verificando arquivos sensiveis:{W}")
    alvos = [
        "/.env", "/.env.local", "/.env.backup",
        "/config.php", "/config.yml", "/config.json",
        "/wp-config.php", "/database.yml", "/settings.py",
        "/backup.sql", "/backup.zip", "/dump.sql",
        "/.git/config", "/.git/HEAD",
        "/id_rsa", "/id_rsa.pub",
        "/phpinfo.php", "/info.php", "/test.php",
        "/server-status", "/server-info",
        "/web.config", "/app.config",
        "/composer.json", "/package.json",
        "/readme.txt", "/CHANGELOG.md",
    ]
    encontrados = []
    for caminho in alvos:
        try:
            resp = requests.get(f"http://{dominio}{caminho}",
                timeout=3, headers=HEADERS, allow_redirects=False)
            if resp.status_code == 200:
                linha = f"{R}[!] EXPOSTO [{resp.status_code}]:{W} {dominio}{caminho}"
                print(linha); encontrados.append(linha)
            elif resp.status_code == 403:
                linha = f"{Y}[~] Bloqueado [403]:{W} {dominio}{caminho}"
                print(linha); encontrados.append(linha)
        except:
            pass
    if not encontrados:
        print(f"{G}[ok] Nenhum arquivo sensivel encontrado{W}")

# ─────────────────────────────────────────
def testar_metodos_http(dominio):
    print(f"\n{C}[*] Testando metodos HTTP perigosos:{W}")
    metodos = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH", "OPTIONS"]
    for metodo in metodos:
        try:
            resp = requests.request(metodo, f"http://{dominio}/",
                timeout=3, headers=HEADERS)
            if resp.status_code not in [405, 501]:
                print(f"{R}[!] Metodo {metodo} permitido:{W} [{resp.status_code}]")
            else:
                print(f"{G}[ok] {metodo}:{W} bloqueado [{resp.status_code}]")
        except:
            pass

# ─────────────────────────────────────────
def testar_headers_seguranca(dominio):
    print(f"\n{C}[*] Headers de seguranca:{W}")
    try:
        r = requests.get(f"http://{dominio}", timeout=5, headers=HEADERS)
        checks = {
            "X-Frame-Options": "Protecao Clickjacking",
            "X-XSS-Protection": "Protecao XSS",
            "X-Content-Type-Options": "Protecao MIME",
            "Strict-Transport-Security": "HSTS",
            "Content-Security-Policy": "CSP",
            "Referrer-Policy": "Referrer Policy",
        }
        for h, desc in checks.items():
            if h in r.headers:
                print(f"{G}[✓] {h}:{W} {desc} — PRESENTE")
            else:
                print(f"{R}[✗] {h}:{W} {desc} — AUSENTE")
        servidor = r.headers.get("Server", "nao exposto")
        print(f"{Y}[*] Servidor:{W} {servidor}")
    except Exception as e:
        print(f"{Y}[-] Erro: {e}{W}")

# ─────────────────────────────────────────
def executar_vulns(alvo, output=None):
    print(f"\n{C}[*] Verificando vulnerabilidades em: {alvo}{W}")
    resultados = []
    dominio = alvo.replace("https://","").replace("http://","").split("/")[0]
    url = f"http://{dominio}"

    testar_headers_seguranca(dominio)
    testar_sqli(url)
    testar_xss(url)
    testar_arquivos_sensiveis(dominio)
    testar_metodos_http(dominio)

    if output:
        with open(output, "w") as f:
            f.write(f"Vulns em {alvo}\n")
        print(f"\n{G}[+] Salvo em: {output}{W}")

    print(f"\n{G}[✓] Verificacao concluida.{W}\n")
