#!/usr/bin/env bash
# run_all.sh — Roda TODOS os cenários (A, B, C) para TCP e R-UDP.
#
# Uso:
#   ./run_all.sh           → 10 execuções por cenário (padrão)

set -euo pipefail

RUNS="${1:-10}"
ONLY="${2:-all}"

SCENARIOS=("A" "B" "C")
COMPOSE="docker compose -f docker/docker-compose.yml"

GREEN="\033[1;32m"; RED="\033[1;31m"; YELLOW="\033[1;33m"; BOLD="\033[1m"; RESET="\033[0m"
log()  { echo -e "${BOLD}[$(date +%H:%M:%S)]${RESET} $*"; }
ok()   { echo -e "${GREEN}✓${RESET} $*"; }
warn() { echo -e "${YELLOW}⚠${RESET} $*"; }
fail() { echo -e "${RED}✗${RESET} $*"; }

mkdir -p logs data

if [[ ! -f data/test.bin ]]; then
  log "Gerando data/test.bin (5 MB)…"
  dd if=/dev/urandom of=data/test.bin bs=1M count=5 status=progress
fi

run_scenario() {
  local PROTO="$1"
  local SCENARIO="$2"

  if [[ "$PROTO" == "tcp" ]]; then
    SERVER_SVC="tcp_server"; CLIENT_SVC="tcp_client"
    SERVER_CTR="redes2_tcp_server"
    PORT=5000; SCRIPT="tcp_client.py"; HOST="tcp_server"
  else
    SERVER_SVC="rudp_server"; CLIENT_SVC="rudp_client"
    SERVER_CTR="redes2_rudp_server"
    PORT=5001; SCRIPT="rudp_client.py"; HOST="rudp_server"
  fi

  local LOG_JSON="/logs/${SCENARIO}_${PROTO}.json"
  local PCAP_HOST="logs/${SCENARIO}_${PROTO}.pcap"

  echo ""
  echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  log "Protocolo=${PROTO^^}  Cenário=${SCENARIO}  Runs=${RUNS}"
  echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

  # Exporta SCENARIO ANTES do up — o compose passa para o container via environment
  export SCENARIO

  # 1. Derruba containers antigos
  log "Limpando containers anteriores…"
  $COMPOSE --profile "$PROTO" down --remove-orphans 2>/dev/null || true

  # 2. Sobe servidor + sidecar de captura
  log "Subindo ${SERVER_SVC} + capture_${PROTO}…"
  $COMPOSE --profile "$PROTO" up -d --build "$SERVER_SVC" "capture_${PROTO}"

  # 3. Aguarda servidor ficar pronto (até 20 s)
  log "Aguardando servidor…"
  for i in $(seq 1 20); do
    if docker logs "$SERVER_CTR" 2>&1 | grep -qE "Aguardando|Escutando"; then
      ok "Servidor pronto."; break
    fi
    [[ $i -eq 20 ]] && warn "Servidor demorou — continuando mesmo assim."
    sleep 1
  done

  # 4. Aplica tc/netem no servidor
  log "Aplicando tc cenário ${SCENARIO}…"
  docker exec "$SERVER_CTR" bash /scripts/setup_tc.sh "$SCENARIO"

  # 5. Roda o cliente N vezes
  log "Rodando cliente (${RUNS} execuções)…"
  $COMPOSE --profile "$PROTO" run --rm \
    -e "SCENARIO=${SCENARIO}" \
    "$CLIENT_SVC" \
    python3 "$SCRIPT" \
      --file /data/test.bin \
      --host "$HOST" \
      --port "$PORT" \
      --runs "$RUNS" \
      --scenario "$SCENARIO" \
      --log "$LOG_JSON"

  # 6. Derruba tudo — SIGTERM faz tcpdump fechar o .pcap corretamente
  log "Parando containers (fechando .pcap)…"
  $COMPOSE --profile "$PROTO" down

  # 7. Verifica arquivos gerados
  if [[ -f "$PCAP_HOST" ]]; then
    ok "$PCAP_HOST  ($(du -sh "$PCAP_HOST" | cut -f1))"
  else
    fail "$PCAP_HOST não foi gerado!"
  fi
  if [[ -f "logs/${SCENARIO}_${PROTO}.json" ]]; then
    ok "logs/${SCENARIO}_${PROTO}.json  ($(du -sh "logs/${SCENARIO}_${PROTO}.json" | cut -f1))"
  fi
}

# ── Loop principal ─────────────────────────────────────────────────────────────
FAILED=()

for SCENARIO in "${SCENARIOS[@]}"; do
  if [[ "$ONLY" == "all" || "$ONLY" == "tcp" ]]; then
    run_scenario "tcp"  "$SCENARIO" || FAILED+=("tcp_${SCENARIO}")
  fi
  if [[ "$ONLY" == "all" || "$ONLY" == "rudp" ]]; then
    run_scenario "rudp" "$SCENARIO" || FAILED+=("rudp_${SCENARIO}")
  fi
done

# ── Resumo final ───────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}══════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  RESUMO FINAL${RESET}"
echo -e "${BOLD}══════════════════════════════════════════════════${RESET}"

for SCENARIO in "${SCENARIOS[@]}"; do
  for PROTO in tcp rudp; do
    [[ "$ONLY" != "all" && "$ONLY" != "$PROTO" ]] && continue
    JSON_OK="✓"; PCAP_OK="✓"
    [[ ! -f "logs/${SCENARIO}_${PROTO}.json" ]] && JSON_OK="✗"
    [[ ! -f "logs/${SCENARIO}_${PROTO}.pcap" ]] && PCAP_OK="✗"
    printf "  Cenário %-2s | %-4s | JSON %s | PCAP %s\n" \
      "$SCENARIO" "${PROTO^^}" "$JSON_OK" "$PCAP_OK"
  done
done

echo ""
if [[ ${#FAILED[@]} -eq 0 ]]; then
  ok "Todos os cenários concluídos."
  echo ""
  echo "  Próximo passo:"
  echo "    python3 analysis/stats.py --inputs logs/*.json --outdir analysis/out"
else
  fail "Falhas: ${FAILED[*]}"
  exit 1
fi