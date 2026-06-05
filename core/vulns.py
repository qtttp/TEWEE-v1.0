import requests
import socket

R = "\033[1;31m"
G = "\033[1;32m"
Y = "\033[1;33m"
C = "\033[1;36m"
W = "\033[0m"

def executar_vulns(alvo, output=None):
    print(f"\n{C}[*] Verificando vulnerabilidades em: {alvo}{W}\n")
    resultados = []
    dominio = alvo.replace("https://", "").replace("http://", "").split("/")[0]

    # 1. Verifica headers de segurança
    try:
        r = requests.get(f"http://{dominio}", timeout=5)
        headers_seg = {
            "X-Frame-Options": "Proteção contra Clickjacking",
            "X-XSS-Protection": "Proteção XSS",
            "X-Content-Type-Options": "Proteção MIME sniffing",
            "Strict-Transport-Security": "HSTS (força HTTPS)",
            "Content-Security-Policy": "CSP ativo",
            "Referrer-Policy": "Política de Referrer",
        }
        print(f"{Y}[*] Headers de Segurança:{W}")
        for h, desc in headers_seg.items():
            if h in r.headers:
                linha = f"{G}[✓] {h}:{W} {desc} — PRESENTE"
            else:
                linha = f"{R}[✗] {h}:{W} {desc} — AUSENTE"
            print(linha)
            resultados.append(linha)
    except Exception as e:
        print(f"{R}[-] Erro ao verificar headers: {e}{W}")

    # 2. Verifica servidor exposto
    try:
        servidor = r.headers.get("Server", "Não exposto")
        linha = f"\n{Y}[*] Servidor:{W} {servidor}"
        print(linha)
        resultados.append(linha)
    except:
        pass

    # 3. Testa caminhos admin comuns
    print(f"\n{Y}[*] Testando painéis admin:{W}")
    caminhos = ["/admin", "/wp-admin", "/login", "/phpmyadmin", "/panel", "/dashboard"]
    for caminho in caminhos:
        try:
            resp = requests.get(f"http://{dominio}{caminho}", timeout=3)
            if resp.status_code in [200, 301, 302]:
                linha = f"{R}[!] Encontrado:{W} {dominio}{caminho} [{resp.status_code}]"
            else:
                linha = f"{G}[-]{W} {caminho} [{resp.status_code}]"
            print(linha)
            resultados.append(linha)
        except:
            pass

    if output:
        with open(output, "w") as f:
            f.write("\n".join(resultados))
        print(f"\n{G}[+] Salvo em: {output}{W}")

    print(f"\n{G}[✓] Verificação concluída.{W}\n")
