"""rudp_server.py — Servidor UDP confiável (Stop-and-Wait).


Protocolo:
  - Cliente envia SYN com JSON (filename, size)
  - Server ACK do SYN
  - Cliente envia DATA sequenciais (Stop-and-Wait)
  - Server ACK/NACK por pacote (checksum)
  - Cliente envia FIN
  - Server ACK do FIN e fecha sessão
"""

import argparse
import json
import os
import socket
import time
from dataclasses import dataclass

from protocol import (
	CHUNK_SIZE,
	FLAG_ACK,
	FLAG_DATA,
	FLAG_FIN,
	FLAG_NACK,
	FLAG_SYN,
	HEADER_TOTAL_SIZE,
	USING_DEFAULT_AUTH,
	X_CUSTOM_AUTH,
	build_packet,
	compute_checksum,
	parse_packet_header,
)


@dataclass
class Session:
	addr: tuple
	filename: str
	expected_seq: int
	file_size: int
	received_bytes: int
	started_ts: float
	out_path: str
	file_handle: object
	nacks_sent: int = 0
	dup_acks_sent: int = 0


def _send_ack(sock: socket.socket, addr, ack_num: int, flags: int = FLAG_ACK) -> None:
	sock.sendto(build_packet(seq_num=0, ack_num=ack_num, flags=flags, payload=b""), addr)


def run_server(host: str, port: int, output_dir: str) -> None:
	os.makedirs(output_dir, exist_ok=True)

	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.bind((host, port))

	print(f"[RUDP-SERVER] Escutando em {host}:{port} (UDP) …")
	if USING_DEFAULT_AUTH:
		print("[RUDP-SERVER] AVISO: auth está no valor padrão. Configure MATRICULA/NOME ou AUTH_SEED.")

	sessions: dict[tuple, Session] = {}
	session_id = 0

	while True:
		raw, addr = sock.recvfrom(HEADER_TOTAL_SIZE + CHUNK_SIZE + 2048)
		hdr = parse_packet_header(raw)
		if hdr is None:
			continue

		# Valida auth para identificar tráfego corretamente.
		if hdr.get("auth") != X_CUSTOM_AUTH:
			continue

		flags = hdr["flags"]
		seq = hdr["seq_num"]
		payload = hdr["payload"]

		# ── SYN (início) ─────────────────────────────────────────────────────
		if flags & FLAG_SYN:
			try:
				meta = json.loads(payload.decode() or "{}")
				filename = os.path.basename(meta.get("filename", "received.bin"))
				file_size = int(meta.get("size", 0))
			except Exception:
				_send_ack(sock, addr, ack_num=seq, flags=FLAG_NACK)
				continue

			session_id += 1
			out_path = os.path.join(output_dir, f"session{session_id:03d}_{filename}")
			fh = open(out_path, "wb")
			sessions[addr] = Session(
				addr=addr,
				filename=filename,
				expected_seq=1,
				file_size=file_size,
				received_bytes=0,
				started_ts=time.perf_counter(),
				out_path=out_path,
				file_handle=fh,
			)

			_send_ack(sock, addr, ack_num=seq, flags=FLAG_ACK)
			print(f"[RUDP-SERVER] SYN de {addr} -> {filename} ({file_size} bytes)")
			continue

		sess = sessions.get(addr)
		if sess is None:
			# Sem sessão ativa: ignora (ou poderia responder NACK)
			continue

		# ── FIN (final) ──────────────────────────────────────────────────────
		if flags & FLAG_FIN:
			elapsed = time.perf_counter() - sess.started_ts
			throughput = sess.received_bytes / elapsed if elapsed > 0 else 0

			_send_ack(sock, addr, ack_num=seq, flags=FLAG_ACK)

			try:
				sess.file_handle.close()
			finally:
				sessions.pop(addr, None)

			print(
				f"[RUDP-SERVER] ✓ {sess.filename} | {sess.received_bytes} bytes | "
				f"{elapsed:.3f} s | {throughput/1024:.1f} KB/s | nacks={sess.nacks_sent}"
			)
			continue

		# ── DATA (Stop-and-Wait) ─────────────────────────────────────────────
		if not (flags & FLAG_DATA):
			continue

		# Checa checksum manualmente (para poder NACK)
		checksum_ok = (compute_checksum(payload) == hdr["checksum"])
		if not checksum_ok:
			sess.nacks_sent += 1
			_send_ack(sock, addr, ack_num=seq, flags=FLAG_NACK)
			continue

		# Sequência esperada
		if seq == sess.expected_seq:
			sess.file_handle.write(payload)
			sess.received_bytes += len(payload)
			sess.expected_seq += 1
			_send_ack(sock, addr, ack_num=seq, flags=FLAG_ACK)
		elif seq < sess.expected_seq:
			# Duplicata (provável retransmissão)
			sess.dup_acks_sent += 1
			_send_ack(sock, addr, ack_num=seq, flags=FLAG_ACK)
		else:
			# Fora de ordem (não esperado em Stop-and-Wait). Re-ACK do último recebido.
			sess.dup_acks_sent += 1
			_send_ack(sock, addr, ack_num=sess.expected_seq - 1, flags=FLAG_ACK)


if __name__ == "__main__":
	ap = argparse.ArgumentParser(description="Servidor R-UDP (Stop-and-Wait)")
	ap.add_argument("--host", default="0.0.0.0", help="Endereço de escuta")
	ap.add_argument("--port", default=5001, type=int, help="Porta UDP")
	ap.add_argument("--output", default="/tmp/received", help="Diretório de saída")
	args = ap.parse_args()
	run_server(args.host, args.port, args.output)
