#!/usr/bin/env bash
set -euo pipefail

SCENARIO="${1:-}"

if [[ -z "$SCENARIO" ]]; then
	echo "Uso: $0 A|B|C|clear" >&2
	exit 2
fi

DEV="${TC_DEV:-eth0}"

case "$SCENARIO" in
	A)
		LOSS="0%"
		DELAY="10ms"
		;;
	B)
		LOSS="5%"
		DELAY="50ms"
		;;
	C)
		LOSS="10%"
		DELAY="100ms"
		;;
	clear)
		tc qdisc del dev "$DEV" root 2>/dev/null || true
		tc qdisc show dev "$DEV"
		exit 0
		;;
	*)
		echo "Cenário inválido: $SCENARIO (use A, B, C ou clear)" >&2
		exit 2
		;;
esac

# replace funciona mesmo se já existir qdisc
tc qdisc replace dev "$DEV" root netem loss "$LOSS" delay "$DELAY"
tc qdisc show dev "$DEV"