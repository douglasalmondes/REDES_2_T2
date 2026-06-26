"""rudp_client.py — Cliente UDP confiável (Stop-and-Wait).

"""

import argparse
import json
import os
import socket
import time

from protocol import (
	CHUNK_SIZE,
	FLAG_ACK,
	FLAG_DATA,
	FLAG_FIN,
	FLAG_NACK,
	FLAG_SYN,
	MAX_RETRIES,
	TIMEOUT,
	USING_DEFAULT_AUTH,
	build_packet,
	parse_packet_header,
)


def _recv_ack(sock: socket.socket) -> dict | None:
	try:
		raw, _ = sock.recvfrom(2048)
	except socket.timeout:
		return None
	return parse_packet_header(raw)


def _wait_for_ack(sock: socket.socket, want_ack_num: int, max_waits: int) -> tuple[bool, int, int]:
	"""Espera ACK/NACK do `want_ack_num`.

	Retorna (ok, timeouts, nacks).
	"""
	timeouts = 0
	nacks = 0

	for _ in range(max_waits):
		ack = _recv_ack(sock)
		if ack is None:
			timeouts += 1
			continue

		flags = ack.get("flags", 0)
		ack_num = ack.get("ack_num", -1)

		if ack_num != want_ack_num:
			# ACK atrasado/fora de contexto: ignora
			continue

		if flags & FLAG_NACK:
			nacks += 1
			return (False, timeouts, nacks)
		if flags & FLAG_ACK:
			return (True, timeouts, nacks)

	return (False, timeouts, nacks)


def send_file(filepath: str, host: str, port: int, scenario: str = "") -> dict:
	file_size = os.path.getsize(filepath)
	filename = os.path.basename(filepath)

	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.settimeout(TIMEOUT)
	server = (host, port)

	if USING_DEFAULT_AUTH:
		print("[RUDP-CLIENT] AVISO: auth está no valor padrão. Configure MATRICULA/NOME ou AUTH_SEED.")

	# ── Handshake SYN ────────────────────────────────────────────────────────
	meta = json.dumps({"filename": filename, "size": file_size}).encode()
	syn_seq = 0
	syn_pkt = build_packet(seq_num=syn_seq, ack_num=0, flags=FLAG_SYN, payload=meta)

	timeouts_total = 0
	nacks_total = 0
	retrans_total = 0
	pkts_sent = 0

	ok = False
	for attempt in range(MAX_RETRIES):
		sock.sendto(syn_pkt, server)
		pkts_sent += 1
		ok, tmo, nck = _wait_for_ack(sock, want_ack_num=syn_seq, max_waits=1)
		timeouts_total += tmo
		nacks_total += nck
		if ok:
			break
		retrans_total += 1
	if not ok:
		raise TimeoutError("Sem ACK do SYN")

	# ── Envio DATA (Stop-and-Wait) ───────────────────────────────────────────
	seq = 1
	start_ts = time.perf_counter()
	sent_bytes = 0

	with open(filepath, "rb") as f:
		while True:
			chunk = f.read(CHUNK_SIZE)
			if not chunk:
				break

			pkt = build_packet(seq_num=seq, ack_num=0, flags=FLAG_DATA, payload=chunk)

			pkt_ok = False
			for _ in range(MAX_RETRIES):
				sock.sendto(pkt, server)
				pkts_sent += 1

				ack_ok, tmo, nck = _wait_for_ack(sock, want_ack_num=seq, max_waits=1)
				timeouts_total += tmo
				nacks_total += nck
				if ack_ok:
					pkt_ok = True
					break

				retrans_total += 1

			if not pkt_ok:
				raise TimeoutError(f"Sem ACK do pacote seq={seq}")

			sent_bytes += len(chunk)
			seq += 1

	# ── FIN ──────────────────────────────────────────────────────────────────
	fin_seq = seq
	fin_pkt = build_packet(seq_num=fin_seq, ack_num=0, flags=FLAG_FIN, payload=b"")
	ok = False
	for _ in range(MAX_RETRIES):
		sock.sendto(fin_pkt, server)
		pkts_sent += 1
		ok, tmo, nck = _wait_for_ack(sock, want_ack_num=fin_seq, max_waits=1)
		timeouts_total += tmo
		nacks_total += nck
		if ok:
			break
		retrans_total += 1
	if not ok:
		raise TimeoutError("Sem ACK do FIN")

	elapsed = time.perf_counter() - start_ts
	throughput = file_size / elapsed if elapsed > 0 else 0

	result = {
		"protocol": "RUDP",
		"scenario": scenario,
		"filename": filename,
		"size_bytes": file_size,
		"elapsed_s": round(elapsed, 6),
		"throughput_bps": round(throughput, 2),
		"throughput_kbps": round(throughput / 1024, 2),
		"packets_sent": pkts_sent,
		"retransmissions": retrans_total,
		"timeouts": timeouts_total,
		"nacks": nacks_total,
		"timestamp": time.time(),
	}

	print(
		f"[RUDP-CLIENT] ✓ {filename} | {file_size} bytes | {elapsed:.3f} s | "
		f"{throughput/1024:.1f} KB/s | retrans={retrans_total} timeouts={timeouts_total} nacks={nacks_total}"
	)
	sock.close()
	return result


def run_multiple(filepath: str, host: str, port: int, runs: int, log_path: str, scenario: str) -> None:
	results = []
	for i in range(1, runs + 1):
		print(f"[RUDP-CLIENT] Execução {i}/{runs}")
		try:
			r = send_file(filepath, host, port, scenario=scenario)
			results.append(r)
		except Exception as exc:
			print(f"[RUDP-CLIENT] Falha na execução {i}: {exc}")
		time.sleep(0.5)

	if log_path:
		os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)
		with open(log_path, "w") as f:
			json.dump(results, f, indent=2)
		print(f"[RUDP-CLIENT] Log salvo em {log_path}")

	if results:
		bps_list = [r["throughput_bps"] for r in results]
		import statistics

		print(
			f"\n[RUDP-CLIENT] Resumo ({len(results)} execuções):\n"
			f"  Mín:  {min(bps_list)/1024:.1f} KB/s\n"
			f"  Méd:  {statistics.mean(bps_list)/1024:.1f} KB/s\n"
			f"  Máx:  {max(bps_list)/1024:.1f} KB/s\n"
			f"  DP:   {statistics.stdev(bps_list)/1024:.1f} KB/s"
		)


if __name__ == "__main__":
	ap = argparse.ArgumentParser(description="Cliente R-UDP (Stop-and-Wait)")
	ap.add_argument("--file", required=True, help="Arquivo a enviar")
	ap.add_argument("--host", default="server", help="Endereço do servidor")
	ap.add_argument("--port", default=5001, type=int, help="Porta UDP")
	ap.add_argument("--runs", default=1, type=int, help="Número de execuções")
	ap.add_argument("--log", default="", help="Arquivo JSON de log")
	ap.add_argument("--scenario", default="", help="Nome do cenário (A/B/C)")
	args = ap.parse_args()

	if args.runs > 1:
		run_multiple(args.file, args.host, args.port, args.runs, args.log, args.scenario)
	else:
		send_file(args.file, args.host, args.port, scenario=args.scenario)
