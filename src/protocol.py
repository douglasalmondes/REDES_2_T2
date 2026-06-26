"""protocol.py — Definições compartilhadas entre TCP e R-UDP.

Cabeçalho R-UDP (18 bytes fixos):
    - seq_num   : 4 bytes  (uint32, big-endian)
    - ack_num   : 4 bytes  (uint32, big-endian)
    - flags     : 1 byte   (bitmask: SYN=0x01, ACK=0x02, FIN=0x04, DATA=0x08)
    - data_len  : 4 bytes  (uint32, comprimento do payload em bytes)
    - checksum  : 4 bytes  (uint32, CRC-32 do payload)
    - auth_len  : 1 byte   (comprimento do campo auth, sempre 64)

Seguido de:
    - auth      : 64 bytes (SHA-256 hex de MATRICULA+NOME)
    - payload   : data_len bytes

Total overhead por pacote: 18 + 64 = 82 bytes
"""

import hashlib
import os
import struct
import zlib


DEFAULT_MATRICULA = "12345678"
DEFAULT_NOME = "Aluno UFPI"

MATRICULA = os.getenv("MATRICULA", DEFAULT_MATRICULA)
NOME = os.getenv("NOME", DEFAULT_NOME)

AUTH_SEED = os.getenv("AUTH_SEED")
if AUTH_SEED is None:
    AUTH_SEED = MATRICULA + NOME


def compute_x_custom_auth(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


X_CUSTOM_AUTH: str = compute_x_custom_auth(AUTH_SEED)
AUTH_BYTES: bytes = X_CUSTOM_AUTH.encode()  # 64 bytes ASCII

USING_DEFAULT_AUTH: bool = (
    os.getenv("AUTH_SEED") is None
    and os.getenv("MATRICULA") is None
    and os.getenv("NOME") is None
)

# Flags
FLAG_SYN  = 0x01
FLAG_ACK  = 0x02
FLAG_FIN  = 0x04
FLAG_DATA = 0x08
FLAG_NACK = 0x10   

# Tamanhos
HEADER_FIXED_SIZE = 18          # campos numéricos + auth_len
AUTH_SIZE         = 64          # SHA-256 hex sempre tem 64 chars
HEADER_TOTAL_SIZE = HEADER_FIXED_SIZE + AUTH_SIZE   # 82 bytes
CHUNK_SIZE        = 4096        # tamanho do payload de dados
TIMEOUT           = 2.0         # segundos antes de retransmitir
MAX_RETRIES       = 10

# struct format: seq(4) ack(4) flags(1) data_len(4) checksum(4) auth_len(1)
_STRUCT = struct.Struct("!IIBIIB")


def compute_checksum(data: bytes) -> int:
    """CRC-32 do payload (mais robusto que soma simples)."""
    return zlib.crc32(data) & 0xFFFFFFFF


def build_packet(seq_num: int, ack_num: int, flags: int, payload: bytes = b"") -> bytes:
    """Monta um pacote R-UDP completo."""
    checksum = compute_checksum(payload)
    header = _STRUCT.pack(seq_num, ack_num, flags, len(payload), checksum, AUTH_SIZE)
    return header + AUTH_BYTES + payload


def parse_packet(raw: bytes) -> dict | None:
    """
    Decompõe um pacote R-UDP.
    Retorna dict com campos ou None se o pacote for inválido.
    """
    if len(raw) < HEADER_TOTAL_SIZE:
        return None
    try:
        seq_num, ack_num, flags, data_len, checksum, auth_len = _STRUCT.unpack(
            raw[:HEADER_FIXED_SIZE]
        )
        auth = raw[HEADER_FIXED_SIZE: HEADER_FIXED_SIZE + AUTH_SIZE].decode()
        payload = raw[HEADER_TOTAL_SIZE: HEADER_TOTAL_SIZE + data_len]

        # Valida autenticação
        if auth != X_CUSTOM_AUTH:
            return None

        # Valida checksum
        if compute_checksum(payload) != checksum:
            return None

        return {
            "seq_num":  seq_num,
            "ack_num":  ack_num,
            "flags":    flags,
            "data_len": data_len,
            "checksum": checksum,
            "auth":     auth,
            "payload":  payload,
        }
    except Exception:
        return None


def parse_packet_header(raw: bytes) -> dict | None:
    """Parseia apenas header+auth, sem validar checksum/auth.

    Útil para construir ACK/NACK mesmo quando o payload chega corrompido.
    """
    if len(raw) < HEADER_TOTAL_SIZE:
        return None
    try:
        seq_num, ack_num, flags, data_len, checksum, auth_len = _STRUCT.unpack(
            raw[:HEADER_FIXED_SIZE]
        )
        auth = raw[HEADER_FIXED_SIZE: HEADER_FIXED_SIZE + AUTH_SIZE].decode()
        payload = raw[HEADER_TOTAL_SIZE: HEADER_TOTAL_SIZE + data_len]
        return {
            "seq_num": seq_num,
            "ack_num": ack_num,
            "flags": flags,
            "data_len": data_len,
            "checksum": checksum,
            "auth_len": auth_len,
            "auth": auth,
            "payload": payload,
        }
    except Exception:
        return None


def flag_str(flags: int) -> str:
    """Representação legível das flags."""
    parts = []
    if flags & FLAG_SYN:  parts.append("SYN")
    if flags & FLAG_ACK:  parts.append("ACK")
    if flags & FLAG_FIN:  parts.append("FIN")
    if flags & FLAG_DATA: parts.append("DATA")
    if flags & FLAG_NACK: parts.append("NACK")
    return "|".join(parts) if parts else "NONE"