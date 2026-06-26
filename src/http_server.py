"""http_server.py — Miniservidor HTTP/1.1 simplificado.

Pode operar sobre dois transportes diferentes (escolhido por --transport):

  tcp  : socket TCP nativo. Request/response HTTP/1.1 puro, texto, igual
         a um servidor web real simplificado.

  rudp : reaproveita a camada de confiabilidade R-UDP (Stop-and-Wait,
         checksum, ACK/NACK) já implementada na Segunda Avaliação.
         O cliente manda a requisição HTTP como payload do SYN; o
         servidor responde com a mensagem HTTP completa (status line +
         headers + corpo) fragmentada em pacotes DATA, reaproveitando
         exatamente a mesma lógica de envio confiável que o
         rudp_server.py usava para mandar arquivos — só que agora quem
         "envia o arquivo" é o servidor, e o "arquivo" é a resposta HTTP
         inteira montada em memória.
"""

import argparse
import os
import socket
import time

from http_common import build_response, guess_content_type, parse_request, resolve_static_path
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
    USING_DEFAULT_AUTH,
    X_CUSTOM_AUTH,
    build_packet,
    compute_checksum,
    parse_packet_header,
)


def handle_get(www_root: str, url_path: str) -> tuple[int, bytes, str]:
    """Lógica de aplicação compartilhada pelos dois transportes.

    Retorna (status_code, body_bytes, content_type).
    """
    file_path = resolve_static_path(www_root, url_path)

    if not file_path or not os.path.isfile(file_path):
        not_found = os.path.join(www_root, "404.html")
        if os.path.isfile(not_found):
            with open(not_found, "rb") as f:
                body = f.read()
        else:
            body = b"<html><body><h1>404 Not Found</h1></body></html>"
        return 404, body, "text/html"

    with open(file_path, "rb") as f:
        body = f.read()
    return 200, body, guess_content_type(file_path)


# ───────────────────────────── Transporte TCP ──────────────────────────────

def run_tcp(host: str, port: int, www_root: str) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(5)
    print(f"[HTTP/TCP-SERVER] Aguardando conexões em {host}:{port} … www_root={www_root}")

    while True:
        conn, addr = srv.accept()
        try:
            _handle_tcp_connection(conn, addr, www_root)
        except Exception as exc:
            print(f"[HTTP/TCP-SERVER] Erro com {addr}: {exc}")
        finally:
            conn.close()


def _handle_tcp_connection(conn: socket.socket, addr, www_root: str) -> None:
    conn.settimeout(5.0)
    raw = b""
    while b"\r\n\r\n" not in raw:
        chunk = conn.recv(4096)
        if not chunk:
            return
        raw += chunk

    req = parse_request(raw)
    if req is None or req["method"] != "GET":
        body = b"<html><body><h1>400 Bad Request</h1></body></html>"
        resp = build_response(400, "text/html", body)
        conn.sendall(resp)
        return

    t0 = time.perf_counter()
    status, body, ctype = handle_get(www_root, req["path"])
    resp = build_response(status, ctype, body)
    conn.sendall(resp)
    elapsed = time.perf_counter() - t0

    print(f"[HTTP/TCP-SERVER] {addr} GET {req['path']} -> {status} "
          f"({len(body)} bytes, {elapsed*1000:.1f} ms)")


# ───────────────────────────── Transporte R-UDP ────────────────────────────

def _send_ack(sock: socket.socket, addr, ack_num: int, flags: int = FLAG_ACK) -> None:
    sock.sendto(build_packet(seq_num=0, ack_num=ack_num, flags=flags, payload=b""), addr)


def _rudp_send_reliable(sock: socket.socket, addr, payload: bytes) -> dict:
    """Envia `payload` ao cliente em chunks, usando Stop-and-Wait
    (mesmo esquema do rudp_client.py original), mas no sentido
    servidor -> cliente. Retorna métricas de envio."""
    seq = 1
    pkts_sent = 0
    retrans = 0
    timeouts = 0

    offset = 0
    total = len(payload)
    while offset < total:
        chunk = payload[offset: offset + CHUNK_SIZE]
        pkt = build_packet(seq_num=seq, ack_num=0, flags=FLAG_DATA, payload=chunk)

        acked = False
        for _ in range(MAX_RETRIES):
            sock.sendto(pkt, addr)
            pkts_sent += 1
            sock.settimeout(TIMEOUT)
            try:
                raw, raddr = sock.recvfrom(HEADER_TOTAL_SIZE + 2048)
            except socket.timeout:
                timeouts += 1
                retrans += 1
                continue
            hdr = parse_packet_header(raw)
            if hdr is None or raddr != addr:
                continue
            if hdr["flags"] & FLAG_ACK and hdr["ack_num"] == seq:
                acked = True
                break
            if hdr["flags"] & FLAG_NACK and hdr["ack_num"] == seq:
                retrans += 1
                continue
        if not acked:
            raise TimeoutError(f"HTTP/R-UDP: sem ACK do chunk seq={seq}")

        offset += len(chunk)
        seq += 1

    # FIN
    fin_pkt = build_packet(seq_num=seq, ack_num=0, flags=FLAG_FIN, payload=b"")
    for _ in range(MAX_RETRIES):
        sock.sendto(fin_pkt, addr)
        pkts_sent += 1
        sock.settimeout(TIMEOUT)
        try:
            raw, raddr = sock.recvfrom(HEADER_TOTAL_SIZE + 2048)
        except socket.timeout:
            timeouts += 1
            retrans += 1
            continue
        hdr = parse_packet_header(raw)
        if hdr and raddr == addr and hdr["flags"] & FLAG_ACK and hdr["ack_num"] == seq:
            break

    return {"packets_sent": pkts_sent, "retransmissions": retrans, "timeouts": timeouts}


def run_rudp(host: str, port: int, www_root: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    print(f"[HTTP/R-UDP-SERVER] Escutando em {host}:{port} (UDP) … www_root={www_root}")
    if USING_DEFAULT_AUTH:
        print("[HTTP/R-UDP-SERVER] AVISO: auth está no valor padrão. Configure MATRICULA/NOME ou AUTH_SEED.")

    while True:
        sock.settimeout(None)
        raw, addr = sock.recvfrom(HEADER_TOTAL_SIZE + CHUNK_SIZE + 2048)
        hdr = parse_packet_header(raw)
        if hdr is None or hdr.get("auth") != X_CUSTOM_AUTH:
            continue

        if not (hdr["flags"] & FLAG_SYN):
            # Pacotes fora de uma nova "conexão" (ex: ACKs atrasados de uma
            # sessão anterior) são ignorados nesse loop principal.
            continue

        # ACK do SYN imediatamente, depois processa a requisição.
        _send_ack(sock, addr, ack_num=hdr["seq_num"], flags=FLAG_ACK)

        req_raw = hdr["payload"]
        req = parse_request(req_raw)
        t0 = time.perf_counter()

        if req is None or req["method"] != "GET":
            body = b"<html><body><h1>400 Bad Request</h1></body></html>"
            resp = build_response(400, "text/html", body)
            status, path = 400, "?"
        else:
            status, body, ctype = handle_get(www_root, req["path"])
            resp = build_response(status, ctype, body)
            path = req["path"]

        try:
            metrics = _rudp_send_reliable(sock, addr, resp)
        except TimeoutError as exc:
            print(f"[HTTP/R-UDP-SERVER] {addr} ERRO ao enviar resposta: {exc}")
            continue

        elapsed = time.perf_counter() - t0
        print(f"[HTTP/R-UDP-SERVER] {addr} GET {path} -> {status} "
              f"({len(body)} bytes, {elapsed*1000:.1f} ms, "
              f"pkts={metrics['packets_sent']} retrans={metrics['retransmissions']})")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Miniservidor HTTP/1.1 (TCP ou R-UDP)")
    ap.add_argument("--transport", choices=["tcp", "rudp"], required=True)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--www", default="/app/www", help="Diretório raiz dos arquivos estáticos")
    args = ap.parse_args()

    if args.transport == "tcp":
        run_tcp(args.host, args.port, args.www)
    else:
        run_rudp(args.host, args.port, args.www)
