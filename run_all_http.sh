#!/usr/bin/env bash
# run_all_http.sh — Roda TODOS os cenários (A, B, C) para HTTP sobre TCP e
# R-UDP, com resolução DNS prévia, para os 3 tamanhos de arquivo exigidos.
#
# O tc/netem é aplicado na interface do CLIENTE (não do servidor), pois o
# cliente é o nó comum aos dois enlaces lógicos do teste: cliente<->DNS e
# cliente<->servidor-web. Isso garante que a perda/delay simulados afetem
# tanto a resolução de nomes quanto o download HTTP, conforme pedido na
# Pergunta Obrigatória 1 do relatório.
#
# Uso:
#   ./run_all_http.sh                 → 10 execuções por combinação (padrão)
#   ./run_all_http.sh 5                → 5 execuções por combinação
#   ./run_all_http.sh 10 http_tcp      → roda só HTTP/TCP
#   ./run_all_http.sh 10 all file_1mb.bin   → roda só um tamanho de arquivo

set -euo pipefail

RUNS="${1:-10}"
ONLY="${2:-all}"
ONLY_FILE="${3:-all}"

SCENARIOS=("A" "B" "C")
FILES=("file_100kb.bin" "file_1mb.bin" "file_10mb.bin")
DOMAIN="webserver.ufpi.local"
COMPOSE="docker compose -f docker/docker-compose.yml"

GREEN="\033[1;32m"; RED="\033[1;31m"; YELLOW="\033[1;33m"; BOLD="\033[1m"; RESET="\033[0m"
log()  { echo -e "${BOLD}[$(date +%H:%M:%S)]${RESET} $*"; }
ok()   { echo -e "${GREEN}✓${RESET} $*"; }
warn() { echo -e "${YELLOW}⚠${RESET} $*"; }
fail() { echo -e "${RED}✗${RESET} $*"; }

mkdir -p logs

run_scenario() {
  local PROTO="$1"        # http_tcp | http_rudp
  local SCENARIO="$2"     # A | B | C
  local FILE="$3"         # file_100kb.bin | file_1mb.bin | file_10mb.bin

  if [[ "$PROTO" == "http_tcp" ]]; then
    SERVER_SVC="http_tcp_server"; CLIENT_SVC="http_tcp_client"
    SERVER_CTR="redes2_http_tcp_server"; CLIENT_CTR="redes2_http_tcp_client"
    HTTP_PORT=8080; TRANSPORT="tcp"
  else
    SERVER_SVC="http_rudp_server"; CLIENT_SVC="http_rudp_client"
    SERVER_CTR="redes2_http_rudp_server"; CLIENT_CTR="redes2_http_rudp_client"
    HTTP_PORT=8081; TRANSPORT="rudp"
  fi

  local TAG="${SCENARIO}_${PROTO}_${FILE%.bin}"
  local LOG_JSON="/logs/${TAG}.json"
  local PCAP_HOST="logs/${SCENARIO}_${PROTO}.pcap"

  echo ""
  echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  log "Transporte=${TRANSPORT^^}  Cenário=${SCENARIO}  Arquivo=${FILE}  Runs=${RUNS}"
  echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

  export SCENARIO

  # 1. Derruba containers antigos
  log "Limpando containers anteriores…"
  $COMPOSE --profile "$PROTO" down --remove-orphans 2>/dev/null || true

  # 2. Sobe DNS + servidor web + sidecar de captura
  log "Subindo dns_server + ${SERVER_SVC} + capture_${PROTO}…"
  $COMPOSE --profile "$PROTO" up -d --build dns_server "$SERVER_SVC" "capture_${PROTO}"

  # 3. Aguarda servidor web ficar pronto (até 20 s)
  log "Aguardando servidor web…"
  for i in $(seq 1 20); do
    if docker logs "$SERVER_CTR" 2>&1 | grep -qE "Escutando|Aguardando"; then
      ok "Servidor web pronto."; break
    fi
    [[ $i -eq 20 ]] && warn "Servidor demorou — continuando mesmo assim."
    sleep 1
  done

  # 4. Sobe o cliente (sem rodar comando ainda, só para existir o container
  #    onde vamos aplicar o tc antes da requisição)
  log "Subindo container cliente (${CLIENT_SVC})…"
  $COMPOSE --profile "$PROTO" run -d --name "$CLIENT_CTR" \
    -e "SCENARIO=${SCENARIO}" \
    "$CLIENT_SVC" sleep infinity

  # 5. Aplica tc/netem NO CLIENTE (afeta DNS e HTTP igualmente)
  log "Aplicando tc cenário ${SCENARIO} no cliente…"
  docker exec "$CLIENT_CTR" bash /scripts/setup_tc.sh "$SCENARIO"

  # 6. Roda o cliente HTTP (DNS + GET) N vezes
  log "Rodando cliente HTTP (${RUNS} execuções)…"
  docker exec "$CLIENT_CTR" python3 http_client.py \
    --domain "$DOMAIN" \
    --dns-host dns_server \
    --dns-port 5300 \
    --http-port "$HTTP_PORT" \
    --path "/${FILE}" \
    --transport "$TRANSPORT" \
    --runs "$RUNS" \
    --scenario "$SCENARIO" \
    --log "$LOG_JSON"

  # 7. Remove o container cliente
  docker rm -f "$CLIENT_CTR" >/dev/null 2>&1 || true

  # 8. Derruba tudo — SIGTERM faz tcpdump fechar o .pcap corretamente
  log "Parando containers (fechando .pcap)…"
  $COMPOSE --profile "$PROTO" down

  # 9. Verifica arquivos gerados
  if [[ -f "$PCAP_HOST" ]]; then
    ok "$PCAP_HOST  ($(du -sh "$PCAP_HOST" | cut -f1))"
  fi
  if [[ -f "logs/${TAG}.json" ]]; then
    ok "logs/${TAG}.json  ($(du -sh "logs/${TAG}.json" | cut -f1))"
  else
    fail "logs/${TAG}.json não foi gerado!"
  fi
}

# ── Loop principal ─────────────────────────────────────────────────────────────
FAILED=()

for SCENARIO in "${SCENARIOS[@]}"; do
  for FILE in "${FILES[@]}"; do
    [[ "$ONLY_FILE" != "all" && "$ONLY_FILE" != "$FILE" ]] && continue

    if [[ "$ONLY" == "all" || "$ONLY" == "http_tcp" ]]; then
      run_scenario "http_tcp"  "$SCENARIO" "$FILE" || FAILED+=("http_tcp_${SCENARIO}_${FILE}")
    fi
    if [[ "$ONLY" == "all" || "$ONLY" == "http_rudp" ]]; then
      run_scenario "http_rudp" "$SCENARIO" "$FILE" || FAILED+=("http_rudp_${SCENARIO}_${FILE}")
    fi
  done
done

# ── Resumo final ───────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}══════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  RESUMO FINAL${RESET}"
echo -e "${BOLD}══════════════════════════════════════════════════${RESET}"

for SCENARIO in "${SCENARIOS[@]}"; do
  for FILE in "${FILES[@]}"; do
    [[ "$ONLY_FILE" != "all" && "$ONLY_FILE" != "$FILE" ]] && continue
    for PROTO in http_tcp http_rudp; do
      [[ "$ONLY" != "all" && "$ONLY" != "$PROTO" ]] && continue
      TAG="${SCENARIO}_${PROTO}_${FILE%.bin}"
      JSON_OK="✓"
      [[ ! -f "logs/${TAG}.json" ]] && JSON_OK="✗"
      printf "  Cenário %-2s | %-10s | %-14s | JSON %s\n" \
        "$SCENARIO" "$PROTO" "$FILE" "$JSON_OK"
    done
  done
done

echo ""
if [[ ${#FAILED[@]} -eq 0 ]]; then
  ok "Todos os cenários concluídos."
  echo ""
  echo "  Próximo passo:"
  echo "    python3 analysis/stats_http.py --inputs 'logs/*_http_*.json' --outdir analysis/out_http"
else
  fail "Falhas: ${FAILED[*]}"
  exit 1
fi
