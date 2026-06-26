"""tcp_client.py — Cliente de transferência de arquivos via TCP.

"""

import argparse
import json
import os
import socket
import time

from protocol import X_CUSTOM_AUTH

BUFFER = 65536


def send_file(filepath: str, host: str, port: int, scenario: str = "") -> dict:
    """
    Envia *filepath* via TCP e retorna métricas da transferência.
    """
    file_size = os.path.getsize(filepath)
    filename  = os.path.basename(filepath)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))

    try:
        # ── Metadados ─────────────────────────────────────────────────────────
        meta = json.dumps({
            "filename": filename,
            "size":     file_size,
            "auth":     X_CUSTOM_AUTH,
        })
        sock.sendall(meta.encode() + b"\n")

        # ── Corpo do arquivo ──────────────────────────────────────────────────
        start_ts = time.perf_counter()
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(BUFFER)
                if not chunk:
                    break
                sock.sendall(chunk)

        # ── Aguarda confirmação do servidor ───────────────────────────────────
        ack_raw = b""
        while b"\n" not in ack_raw:
            ack_raw += sock.recv(1024)

        elapsed = time.perf_counter() - start_ts
        ack     = json.loads(ack_raw.split(b"\n")[0].decode())

        throughput = file_size / elapsed if elapsed > 0 else 0

        result = {
            "protocol":   "TCP",
            "scenario":   scenario,
            "filename":   filename,
            "size_bytes": file_size,
            "elapsed_s":  round(elapsed, 6),
            "throughput_bps": round(throughput, 2),
            "throughput_kbps": round(throughput / 1024, 2),
            "packets_sent": None,
            "retransmissions": 0,
            "timeouts": 0,
            "nacks": 0,
            "server_ack": ack,
            "timestamp":  time.time(),
        }
        print(
            f"[TCP-CLIENT] ✓ {filename} | {file_size} bytes | "
            f"{elapsed:.3f} s | {throughput / 1024:.1f} KB/s"
        )
        return result

    finally:
        sock.close()


def run_multiple(filepath: str, host: str, port: int, runs: int, log_path: str, scenario: str) -> None:
    results = []
    for i in range(1, runs + 1):
        print(f"[TCP-CLIENT] Execução {i}/{runs}")
        try:
            r = send_file(filepath, host, port, scenario=scenario)
            results.append(r)
        except Exception as exc:
            print(f"[TCP-CLIENT] Falha na execução {i}: {exc}")
        time.sleep(0.5)   # pequena pausa entre execuções

    if log_path:
        os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)
        with open(log_path, "w") as f:
            json.dump(results, f, indent=2)
        print(f"[TCP-CLIENT] Log salvo em {log_path}")

    # Resumo rápido no terminal
    if results:
        bps_list = [r["throughput_bps"] for r in results]
        import statistics
        print(
            f"\n[TCP-CLIENT] Resumo ({len(results)} execuções):\n"
            f"  Mín:  {min(bps_list)/1024:.1f} KB/s\n"
            f"  Méd:  {statistics.mean(bps_list)/1024:.1f} KB/s\n"
            f"  Máx:  {max(bps_list)/1024:.1f} KB/s\n"
            f"  DP:   {statistics.stdev(bps_list)/1024:.1f} KB/s"
        )


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Cliente TCP de transferência de arquivos")
    ap.add_argument("--file", required=True, help="Arquivo a enviar")
    ap.add_argument("--host", default="server",  help="Endereço do servidor")
    ap.add_argument("--port", default=5000, type=int, help="Porta TCP")
    ap.add_argument("--runs", default=1,    type=int, help="Número de execuções")
    ap.add_argument("--log",  default="",           help="Arquivo JSON de log")
    ap.add_argument("--scenario", default="",        help="Nome do cenário (A/B/C)")
    args = ap.parse_args()

    if args.runs > 1:
        run_multiple(args.file, args.host, args.port, args.runs, args.log, args.scenario)
    else:
        send_file(args.file, args.host, args.port, scenario=args.scenario)