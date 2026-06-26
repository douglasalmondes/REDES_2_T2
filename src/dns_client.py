"""
dns_client.py — Cliente DNS minimalista.
"""

import argparse
import random
import socket
import time

from dns_protocol import (
    RCODE_NOERROR,
    build_query,
    parse_response,
    rcode_str,
)

DNS_TIMEOUT = 1.0       # segundos de espera por resposta antes de retransmitir
DNS_MAX_RETRIES = 3     # tentativas máximas na aplicação


def resolve(name: str, dns_host: str, dns_port: int,
            timeout: float = DNS_TIMEOUT, max_retries: int = DNS_MAX_RETRIES) -> dict:
    """Resolve `name` consultando o servidor DNS local.

    Retorna um dict com: ip, rcode, elapsed_s, attempts, timeouts.
    Levanta TimeoutError se nenhuma resposta chegar após max_retries tentativas.
    """
    transaction_id = random.randint(0, 0xFFFF)
    query = build_query(transaction_id, name)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    attempts = 0
    timeouts = 0
    start_ts = time.perf_counter()

    try:
        for attempt in range(1, max_retries + 1):
            attempts = attempt
            sock.sendto(query, (dns_host, dns_port))
            try:
                raw, _ = sock.recvfrom(512)
            except socket.timeout:
                timeouts += 1
                continue

            elapsed = time.perf_counter() - start_ts
            resp = parse_response(raw)
            if resp is None or resp["id"] != transaction_id:
                # Resposta corrompida ou de outra transação: trata como perda
                # e tenta novamente dentro do mesmo loop de retries.
                timeouts += 1
                continue

            return {
                "name": name,
                "ip": resp["ip"],
                "rcode": resp["rcode"],
                "rcode_str": rcode_str(resp["rcode"]),
                "elapsed_s": round(elapsed, 6),
                "attempts": attempts,
                "timeouts": timeouts,
            }

        # Esgotou as tentativas sem resposta válida
        elapsed = time.perf_counter() - start_ts
        raise TimeoutError(
            f"DNS: sem resposta para '{name}' após {attempts} tentativa(s) "
            f"({timeouts} timeout(s), {elapsed:.3f}s)"
        )
    finally:
        sock.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Cliente DNS minimalista (Mini-DNS)")
    ap.add_argument("--name", required=True, help="Nome de domínio a resolver")
    ap.add_argument("--dns-host", default="dns_server", help="Endereço do servidor DNS")
    ap.add_argument("--dns-port", default=5300, type=int, help="Porta do servidor DNS")
    ap.add_argument("--timeout", default=DNS_TIMEOUT, type=float, help="Timeout por tentativa (s)")
    ap.add_argument("--retries", default=DNS_MAX_RETRIES, type=int, help="Máximo de tentativas")
    args = ap.parse_args()

    try:
        result = resolve(args.name, args.dns_host, args.dns_port, args.timeout, args.retries)
        if result["rcode"] == RCODE_NOERROR:
            print(f"[DNS-CLIENT] {result['name']} -> {result['ip']} "
                  f"({result['elapsed_s']*1000:.1f} ms, tentativas={result['attempts']}, "
                  f"timeouts={result['timeouts']})")
        else:
            print(f"[DNS-CLIENT] {result['name']} -> {result['rcode_str']} "
                  f"({result['elapsed_s']*1000:.1f} ms)")
    except TimeoutError as exc:
        print(f"[DNS-CLIENT] ERRO: {exc}")
