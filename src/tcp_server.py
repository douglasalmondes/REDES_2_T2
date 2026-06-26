"""
tcp_server.py — Servidor de transferência de arquivos via TCP.
"""

import argparse
import json
import os
import socket
import time

from protocol import X_CUSTOM_AUTH

BUFFER = 65536


def run_server(host: str, port: int, output_dir: str) -> None:
    os.makedirs(output_dir, exist_ok=True)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(5)
    print(f"[TCP-SERVER] Aguardando conexões em {host}:{port} …")

    session = 0
    while True:
        conn, addr = srv.accept()
        session += 1
        print(f"[TCP-SERVER] Conexão #{session} de {addr}")
        _handle(conn, addr, output_dir, session)


def _handle(conn: socket.socket, addr, output_dir: str, session: int) -> None:
    try:
        # ── Recebe metadados (linha JSON terminada em \n) ─────────────────────
        meta_raw = b""
        while b"\n" not in meta_raw:
            chunk = conn.recv(1024)
            if not chunk:
                return
            meta_raw += chunk

        meta_line, rest = meta_raw.split(b"\n", 1)
        meta = json.loads(meta_line.decode())

        filename  = os.path.basename(meta["filename"])
        file_size = meta["size"]
        auth      = meta.get("auth", "")

        print(f"[TCP-SERVER]  arquivo={filename}  tamanho={file_size}  auth={auth[:16]}…")

        if auth != X_CUSTOM_AUTH:
            print("[TCP-SERVER] AVISO: X-Custom-Auth não bate!")

        # ── Recebe corpo do arquivo ───────────────────────────────────────────
        start_ts  = time.perf_counter()
        received  = rest
        while len(received) < file_size:
            chunk = conn.recv(BUFFER)
            if not chunk:
                break
            received += chunk

        elapsed    = time.perf_counter() - start_ts
        throughput = len(received) / elapsed if elapsed > 0 else 0

        # ── Salva arquivo ─────────────────────────────────────────────────────
        out_path = os.path.join(output_dir, f"session{session:03d}_{filename}")
        with open(out_path, "wb") as f:
            f.write(received)

        # ── Resposta de confirmação ───────────────────────────────────────────
        ack = json.dumps({
            "status":     "ok",
            "received":   len(received),
            "elapsed":    round(elapsed, 6),
            "throughput": round(throughput, 2),
        })
        conn.sendall(ack.encode() + b"\n")

        print(
            f"[TCP-SERVER] ✓ {filename} | {len(received)} bytes | "
            f"{elapsed:.3f} s | {throughput / 1024:.1f} KB/s"
        )

    except Exception as exc:
        print(f"[TCP-SERVER] Erro: {exc}")
    finally:
        conn.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Servidor TCP de transferência de arquivos")
    ap.add_argument("--host",   default="0.0.0.0",    help="Endereço de escuta")
    ap.add_argument("--port",   default=5000, type=int, help="Porta TCP")
    ap.add_argument("--output", default="/tmp/received", help="Diretório de saída")
    args = ap.parse_args()
    run_server(args.host, args.port, args.output)