"""dns_server.py — Servidor DNS minimalista (UDP nativo, sem retransmissão).

Responde consultas do tipo A (IPv4) com base em um arquivo de zona estático
(hosts.txt), no formato simplificado definido em dns_protocol.py.

Formato do hosts.txt (uma entrada por linha, comentários com #):
    # nome.dominio        IP
    webserver.ufpi.local  172.20.0.10
"""

import argparse
import os
import socket
import time

from dns_protocol import (
    QTYPE_A,
    RCODE_NOERROR,
    RCODE_NXDOMAIN,
    build_response,
    parse_query,
)

BUFFER = 512  # mensagens DNS simplificadas são pequenas


def load_zone(path: str) -> dict:
    """Lê o arquivo de zona estático e retorna {nome: ip}."""
    zone = {}
    if not os.path.exists(path):
        print(f"[DNS-SERVER] AVISO: arquivo de zona '{path}' não encontrado.")
        return zone

    with open(path, "r") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) != 2:
                print(f"[DNS-SERVER] AVISO: linha {line_no} ignorada (formato inválido): {line!r}")
                continue
            name, ip = parts
            zone[name.lower()] = ip
    return zone


def run_server(host: str, port: int, zone_path: str, reload_interval: float = 5.0) -> None:
    zone = load_zone(zone_path)
    print(f"[DNS-SERVER] Zona carregada: {len(zone)} registro(s) de {zone_path}")
    for name, ip in zone.items():
        print(f"  {name:<30} A  {ip}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    sock.settimeout(reload_interval)
    print(f"[DNS-SERVER] Escutando em {host}:{port} (UDP) …")

    last_reload = time.time()

    while True:
        try:
            raw, addr = sock.recvfrom(BUFFER)
        except socket.timeout:
            # Aproveita o timeout periódico para recarregar a zona, caso o
            # hosts.txt tenha sido alterado (útil para testes manuais).
            if time.time() - last_reload >= reload_interval:
                zone = load_zone(zone_path)
                last_reload = time.time()
            continue

        query = parse_query(raw)
        if query is None:
            print(f"[DNS-SERVER] Pacote malformado de {addr}, ignorado.")
            continue

        name = query["name"].lower()
        tid = query["id"]

        if query["qtype"] != QTYPE_A:
            resp = build_response(tid, query["name"], None, rcode=RCODE_NXDOMAIN)
            sock.sendto(resp, addr)
            continue

        ip = zone.get(name)
        if ip is None:
            print(f"[DNS-SERVER] id={tid} {addr} -> {name} : NXDOMAIN")
            resp = build_response(tid, query["name"], None, rcode=RCODE_NXDOMAIN)
        else:
            print(f"[DNS-SERVER] id={tid} {addr} -> {name} : {ip}")
            resp = build_response(tid, query["name"], ip, rcode=RCODE_NOERROR)

        sock.sendto(resp, addr)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Servidor DNS minimalista (Mini-DNS)")
    ap.add_argument("--host", default="0.0.0.0", help="Endereço de escuta")
    ap.add_argument("--port", default=5300, type=int,
                     help="Porta UDP (padrão 5300; use 53 se rodar como root)")
    ap.add_argument("--zone", default="/app/hosts.txt", help="Arquivo de zona estático")
    args = ap.parse_args()
    run_server(args.host, args.port, args.zone)
