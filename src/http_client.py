"""
http_client.py — Cliente do miniservidor HTTP/1.1.

Fluxo obrigatório (arquitetura da Internet, conforme enunciado):
    1. Resolve o nome do servidor web via Mini-DNS (UDP nativo, porta 5300).
    2. Com o IP em mãos, faz a requisição HTTP GET via TCP nativo OU via
       R-UDP (escolhido por --transport).

Cada execução produz métricas separadas de tempo de resolução DNS e tempo
de download HTTP, permitindo a "Validação Cruzada" pedida no enunciado.
"""

import argparse
import json
import os
import socket
import time

import dns_client
from http_common import build_request, parse_response_head
from protocol import (
    CHUNK_SIZE,
    FLAG_ACK,
    FLAG_DATA,
    FLAG_FIN,
    FLAG_NACK,
    FLAG_SYN,
    HEADER_TOTAL_SIZE,
    MAX_RETRIES,
    TIMEOUT,
    X_CUSTOM_AUTH,
    build_packet,
    parse_packet_header,
)


# ───────────────────────────── Transporte TCP ──────────────────────────────

def _http_get_tcp(ip: str, port: int, path: str, host_header: str) -> dict:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10.0)

    t0 = time.perf_counter()
    sock.connect((ip, port))
    req = build_request("GET", path, host_header)
    sock.sendall(req)

    raw = b""
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        raw += chunk
    elapsed = time.perf_counter() - t0
    sock.close()

    head = parse_response_head(raw)
    if head is None:
        raise ValueError("Resposta HTTP malformada (TCP)")

    body = raw[head["body_start"]:]
    return {
        "status": head["status"],
        "headers": head["headers"],
        "body_len": len(body),
        "elapsed_s": round(elapsed, 6),
        "packets_sent": None,
        "retransmissions": 0,
        "timeouts": 0,
    }


# ───────────────────────────── Transporte R-UDP ────────────────────────────

def _wait_for_ack_or_data(sock: socket.socket) -> dict | None:
    try:
        raw, _ = sock.recvfrom(HEADER_TOTAL_SIZE + CHUNK_SIZE + 2048)
    except socket.timeout:
        return None
    return parse_packet_header(raw)


def _http_get_rudp(ip: str, port: int, path: str, host_header: str) -> dict:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)
    server = (ip, port)

    req_payload = build_request("GET", path, host_header)

    t0 = time.perf_counter()
    pkts_sent = 0
    retrans = 0
    timeouts = 0

    # ── Envia a requisição como payload do SYN ──────────────────────────
    syn_seq = 0
    syn_pkt = build_packet(seq_num=syn_seq, ack_num=0, flags=FLAG_SYN, payload=req_payload)

    syn_acked = False
    for _ in range(MAX_RETRIES):
        sock.sendto(syn_pkt, server)
        pkts_sent += 1
        hdr = _wait_for_ack_or_data(sock)
        if hdr is None:
            timeouts += 1
            retrans += 1
            continue
        if hdr["flags"] & FLAG_ACK and hdr["ack_num"] == syn_seq:
            syn_acked = True
            break
    if not syn_acked:
        raise TimeoutError("HTTP/R-UDP: sem ACK do SYN (requisição)")

    # ── Recebe a resposta HTTP em DATA chunks (Stop-and-Wait) ───────────
    expected_seq = 1
    body_buf = b""
    while True:
        hdr = _wait_for_ack_or_data(sock)
        if hdr is None:
            timeouts += 1
            continue

        flags = hdr["flags"]
        seq = hdr["seq_num"]

        if flags & FLAG_FIN:
            ack_pkt = build_packet(seq_num=0, ack_num=seq, flags=FLAG_ACK, payload=b"")
            sock.sendto(ack_pkt, server)
            break

        if not (flags & FLAG_DATA):
            continue

        if seq == expected_seq:
            body_buf += hdr["payload"]
            ack_pkt = build_packet(seq_num=0, ack_num=seq, flags=FLAG_ACK, payload=b"")
            sock.sendto(ack_pkt, server)
            expected_seq += 1
        else:
            # Duplicata ou fora de ordem: reenvia ACK do último em ordem
            ack_pkt = build_packet(seq_num=0, ack_num=expected_seq - 1, flags=FLAG_ACK, payload=b"")
            sock.sendto(ack_pkt, server)
            retrans += 1

    elapsed = time.perf_counter() - t0

    head = parse_response_head(body_buf)
    if head is None:
        raise ValueError("Resposta HTTP malformada (R-UDP)")
    body = body_buf[head["body_start"]:]

    return {
        "status": head["status"],
        "headers": head["headers"],
        "body_len": len(body),
        "elapsed_s": round(elapsed, 6),
        "packets_sent": pkts_sent,
        "retransmissions": retrans,
        "timeouts": timeouts,
    }


# ───────────────────────────── Fluxo completo ──────────────────────────────

def fetch(domain: str, dns_host: str, dns_port: int, http_port: int, path: str,
          transport: str, scenario: str = "") -> dict:
    """Fluxo completo: resolve DNS, depois faz o GET. Retorna métricas combinadas."""

    # 1) Resolução DNS
    dns_result = dns_client.resolve(domain, dns_host, dns_port)
    ip = dns_result["ip"]
    if ip is None:
        raise RuntimeError(f"DNS não resolveu '{domain}' ({dns_result['rcode_str']})")

    # 2) Requisição HTTP
    if transport == "tcp":
        http_result = _http_get_tcp(ip, http_port, path, domain)
    else:
        http_result = _http_get_rudp(ip, http_port, path, domain)

    total_elapsed = dns_result["elapsed_s"] + http_result["elapsed_s"]

    result = {
        "transport": transport.upper(),
        "scenario": scenario,
        "domain": domain,
        "resolved_ip": ip,
        "path": path,
        "status": http_result["status"],
        "body_len": http_result["body_len"],
        "size_bytes": http_result["body_len"],
        "dns_elapsed_s": dns_result["elapsed_s"],
        "dns_attempts": dns_result["attempts"],
        "dns_timeouts": dns_result["timeouts"],
        "http_elapsed_s": http_result["elapsed_s"],
        "total_elapsed_s": round(total_elapsed, 6),
        "elapsed_s": round(total_elapsed, 6),
        "throughput_bps": round(http_result["body_len"] / http_result["elapsed_s"], 2) if http_result["elapsed_s"] > 0 else 0,
        "packets_sent": http_result["packets_sent"],
        "retransmissions": http_result["retransmissions"],
        "timeouts": http_result["timeouts"],
        "x_custom_auth_ok": http_result["headers"].get("x-custom-auth") == X_CUSTOM_AUTH,
        "content_type": http_result["headers"].get("content-type"),
        "header_overhead_bytes": None,  # preenchido pelo chamador, se quiser medir
        "timestamp": time.time(),
    }

    result["throughput_kbps"] = round(result["throughput_bps"] / 1024, 2)

    print(
        f"[HTTP-CLIENT/{transport.upper()}] {domain}{path} -> {http_result['status']} | "
        f"DNS={dns_result['elapsed_s']*1000:.1f}ms HTTP={http_result['elapsed_s']*1000:.1f}ms | "
        f"{http_result['body_len']} bytes | retrans={http_result['retransmissions']}"
    )
    return result


def run_multiple(domain: str, dns_host: str, dns_port: int, http_port: int, path: str,
                  transport: str, runs: int, log_path: str, scenario: str) -> None:
    results = []
    for i in range(1, runs + 1):
        print(f"[HTTP-CLIENT] Execução {i}/{runs}")
        try:
            r = fetch(domain, dns_host, dns_port, http_port, path, transport, scenario)
            results.append(r)
        except Exception as exc:
            print(f"[HTTP-CLIENT] Falha na execução {i}: {exc}")
        time.sleep(0.3)

    if log_path:
        os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)
        with open(log_path, "w") as f:
            json.dump(results, f, indent=2)
        print(f"[HTTP-CLIENT] Log salvo em {log_path}")

    if results:
        import statistics
        bps = [r["throughput_bps"] for r in results if r["throughput_bps"]]
        dns_ms = [r["dns_elapsed_s"] * 1000 for r in results]
        if bps:
            print(
                f"\n[HTTP-CLIENT] Resumo ({len(results)} execuções):\n"
                f"  Throughput médio: {statistics.mean(bps)/1024:.1f} KB/s\n"
                f"  DNS médio:        {statistics.mean(dns_ms):.1f} ms"
            )


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Cliente HTTP/1.1 com resolução DNS prévia")
    ap.add_argument("--domain", required=True, help="Nome de domínio do servidor web (ex: webserver.ufpi.local)")
    ap.add_argument("--dns-host", default="dns_server")
    ap.add_argument("--dns-port", default=5300, type=int)
    ap.add_argument("--http-port", required=True, type=int)
    ap.add_argument("--path", default="/index.html", help="Caminho do recurso (ex: /index.html)")
    ap.add_argument("--transport", choices=["tcp", "rudp"], required=True)
    ap.add_argument("--runs", default=1, type=int)
    ap.add_argument("--log", default="")
    ap.add_argument("--scenario", default="")
    args = ap.parse_args()

    if args.runs > 1:
        run_multiple(args.domain, args.dns_host, args.dns_port, args.http_port, args.path,
                     args.transport, args.runs, args.log, args.scenario)
    else:
        fetch(args.domain, args.dns_host, args.dns_port, args.http_port, args.path,
              args.transport, args.scenario)
