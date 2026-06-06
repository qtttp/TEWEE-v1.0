#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# T.E.W.E.E - The Eye that Wipes Everything and Everyone

import argparse
import sys

R = "\033[1;31m"
G = "\033[1;32m"
Y = "\033[1;33m"
C = "\033[1;36m"
W = "\033[0m"

BANNER = (
    f"\n{R}"
    "  _____ _______          _______ ______ \n"
    " |_   _|  ___\\ \\        / /  ___|  ____|\n"
    "   | | | |__  \\ \\  /\\  / /| |__ | |__  \n"
    "   | | |  __|  \\ \\/  \\/ / |  __||  __| \n"
    "  _| |_| |___   \\  /\\  /  | |___| |___ \n"
    " |_____|_____|   \\/  \\/   |_____|_____|\n"
    f"{W}\n"
    f"{C}The Eye that Wipes Everything and Everyone{W}\n"
    f"{Y}          [ by: voce | v3.0 ]{W}\n"
)

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="TEWEE - Ferramenta de OSINT, Scan e Automacao",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("--alvo", "-a", metavar="ALVO",
        help="IP, dominio ou URL do alvo")
    parser.add_argument("--ip", metavar="IP/DOMINIO",
        help="Lookup de IP (use 'meu' para seu proprio IP)")
    parser.add_argument("--osint", action="store_true",
        help="Coleta informacoes OSINT do alvo")
    parser.add_argument("--investiga", metavar="DOMINIO",
        help="Investigacao completa: WHOIS, IP, headers, perfis, gateway")
    parser.add_argument("--scan", metavar="TIPO",
        choices=["portas", "rapido", "completo"],
        help="Scanner de portas: portas / rapido / completo")
    parser.add_argument("--vulns", action="store_true",
        help="Busca vulnerabilidades no alvo")
    parser.add_argument("--auto", metavar="TAREFA",
        choices=["update", "limpeza", "info", "backup"],
        help="Automacoes: update / limpeza / info / backup")
    parser.add_argument("--output", "-o", metavar="ARQUIVO",
        help="Salva resultado em arquivo .txt")

    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        print(f"\n{Y}Exemplos:{W}")
        print(f"  tewee --investiga wkvault.com")
        print(f"  tewee --ip meu")
        print(f"  tewee --ip 8.8.8.8")
        print(f"  tewee --alvo google.com --osint")
        print(f"  tewee --alvo google.com --scan rapido")
        print(f"  tewee --alvo google.com --vulns")
        sys.exit(0)

    if args.ip:
        from core.iplookup import lookup_ip
        lookup_ip(args.ip, args.output)

    if args.investiga:
        from core.investiga import executar_investiga
        executar_investiga(args.investiga, args.output)

    if args.osint:
        if not args.alvo:
            print(f"{R}[ERRO]{W} Use --alvo com --osint")
            sys.exit(1)
        from core.osint import executar_osint
        executar_osint(args.alvo, args.output)

    if args.scan:
        if not args.alvo:
            print(f"{R}[ERRO]{W} Use --alvo com --scan")
            sys.exit(1)
        from core.scanner import executar_scan
        executar_scan(args.alvo, args.scan, args.output)

    if args.vulns:
        if not args.alvo:
            print(f"{R}[ERRO]{W} Use --alvo com --vulns")
            sys.exit(1)
        from core.vulns import executar_vulns
        executar_vulns(args.alvo, args.output)

    if args.auto:
        from core.automation import executar_auto
        executar_auto(args.auto)

if __name__ == "__main__":
    main()
