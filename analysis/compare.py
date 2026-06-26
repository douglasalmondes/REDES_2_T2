"""compare.py — Compara métricas da aplicação (JSON) com capturas de rede (CSV).

Para cada par CENARIO_PROTO encontrado em logs/, cruza:
  - JSON  : throughput_kbps, elapsed_s, size_bytes  (gerados pelo cliente)
  - CSV   : throughput_kbps, duration_s, bytes_total (gerados pelo tshark)

Saídas:
  - comparison_summary.csv   — tabela consolidada de todas as comparações
  - comparison_report.txt    — relatório legível para colar no trabalho
  - 07_comparison_bar.png    — throughput aplicação vs rede por cenário
  - 08_comparison_volume.png — volume de dados aplicação vs rede
  - 09_comparison_time.png   — tempo aplicação vs rede
"""

import argparse
import glob
import json
import os
from pathlib import Path

import pandas as pd


SCENARIOS = ["A", "B", "C"]
PROTOS    = ["tcp", "rudp"]
COLORS    = {
    "app":  {"tcp": "#2196F3", "rudp": "#FF5722"},
    "net":  {"tcp": "#90CAF9", "rudp": "#FFCCBC"},
}
SCENARIO_LABELS = {
    "A": "A (0% loss/10ms)",
    "B": "B (5% loss/50ms)",
    "C": "C (10% loss/100ms)",
}


# ── Carregamento ──────────────────────────────────────────────────────────────

def load_json(path: str) -> pd.DataFrame:
    with open(path) as f:
        data = json.load(f)
    return pd.DataFrame(data) if data else pd.DataFrame()


def load_conversations_csv(path: str) -> pd.DataFrame:
    return pd.read_csv(path)


def find_pairs(logsdir: str) -> list[dict]:
    pairs = []

    for scenario in SCENARIOS:
        for proto in PROTOS:
            json_ = os.path.join(logsdir, f"{scenario}_{proto}.json")

            conv = os.path.join(
                logsdir,
                "pcaps_csv",  
                f"{scenario}_{proto}_conversations.csv"
            )

            if os.path.exists(json_) and os.path.exists(conv):
                pairs.append({
                    "scenario": scenario,
                    "proto": proto,
                    "json": json_,
                    "conv_csv": conv,
                })

    return pairs


# ── Métricas da aplicação (JSON) ──────────────────────────────────────────────

def app_metrics(df: pd.DataFrame) -> dict:
    """Agrega todas as execuções de um JSON em métricas médias."""
    return {
        "app_runs":           len(df),
        "app_size_bytes_mean": df["size_bytes"].mean(),
        "app_elapsed_s_mean":  df["elapsed_s"].mean(),
        "app_elapsed_s_std":   df["elapsed_s"].std(),
        "app_throughput_kbps_mean": df["throughput_kbps"].mean(),
        "app_throughput_kbps_std":  df["throughput_kbps"].std(),
    }


# ── Métricas da rede (conversations CSV) ─────────────────────────────────────

def net_metrics(df: pd.DataFrame, proto: str, port: int) -> dict:
    """
    Filtra a conversa principal (pela porta do servidor) e extrai métricas.
    Soma todas as conversas da porta relevante para cobrir múltiplas execuções.
    """
    port_col = "src_port" if proto == "tcp" else "src_port"

    # Filtra conversas que envolvem a porta do servidor (5000=TCP / 5001=RUDP)
    mask = (df["src_port"] == port) | (df["dst_port"] == port)
    rel  = df[mask].copy()

    if rel.empty:
        return {
            "net_conversations":      0,
            "net_bytes_total_mean":   None,
            "net_duration_s_mean":    None,
            "net_throughput_kbps_mean": None,
            "net_overhead_pct":       None,
        }

    return {
        "net_conversations":        len(rel),
        "net_bytes_total_mean":     rel["bytes_total"].mean(),
        "net_bytes_total_std":      rel["bytes_total"].std(),
        "net_duration_s_mean":      rel["duration_s"].mean(),
        "net_duration_s_std":       rel["duration_s"].std(),
        "net_throughput_kbps_mean": rel["throughput_kbps"].mean(),
        "net_throughput_kbps_std":  rel["throughput_kbps"].std(),
    }


def overhead_pct(app_bytes: float, net_bytes: float) -> float:
    """% de overhead de rede em relação ao payload da aplicação."""
    if app_bytes and net_bytes and app_bytes > 0:
        return round((net_bytes - app_bytes) / app_bytes * 100, 2)
    return None


def delta_pct(app_val: float, net_val: float) -> float:
    """Diferença percentual: (app - net) / net * 100."""
    if app_val and net_val and net_val > 0:
        return round((app_val - net_val) / net_val * 100, 2)
    return None


# ── Relatório texto ───────────────────────────────────────────────────────────

def write_report(rows: list[dict], out_path: str) -> None:
    lines = []
    lines.append("=" * 64)
    lines.append("  RELATÓRIO DE COMPARAÇÃO — Aplicação vs Rede (Wireshark)")
    lines.append("=" * 64)
    lines.append("")

    for r in rows:
        scen  = r["scenario"]
        proto = r["proto"].upper()
        lines.append(f"┌─ Cenário {scen} │ {proto} {'─'*(44 - len(proto))}")

        # Volume
        ab = r.get("app_size_bytes_mean")
        nb = r.get("net_bytes_total_mean")
        oh = r.get("overhead_pct")
        lines.append(f"│  Volume de dados")
        lines.append(f"│    Aplicação  : {ab/1024:.1f} KB  (payload enviado)" if ab else "│    Aplicação  : N/A")
        lines.append(f"│    Rede       : {nb/1024:.1f} KB  (frame completo c/ headers)" if nb else "│    Rede       : N/A")
        lines.append(f"│    Overhead   : {oh:+.2f}%  ({'OK — esperado p/ headers IP/TCP/UDP' if oh and oh < 5 else 'VERIFICAR' if oh else 'N/A'})" if oh is not None else "│    Overhead   : N/A")
        lines.append(f"│")

        # Tempo
        at = r.get("app_elapsed_s_mean")
        nt = r.get("net_duration_s_mean")
        dt = r.get("delta_time_pct")
        lines.append(f"│  Tempo de transferência")
        lines.append(f"│    Aplicação  : {at:.4f} s  (medido na camada de aplicação)" if at else "│    Aplicação  : N/A")
        lines.append(f"│    Rede       : {nt:.4f} s  (primeiro→último pacote no pcap)" if nt else "│    Rede       : N/A")
        lines.append(f"│    Diferença  : {dt:+.2f}%  ({'OK' if dt and abs(dt) < 10 else 'VERIFICAR' if dt else 'N/A'})" if dt is not None else "│    Diferença  : N/A")
        lines.append(f"│")

        # Throughput
        ak = r.get("app_throughput_kbps_mean")
        nk = r.get("net_throughput_kbps_mean")
        dk = r.get("delta_throughput_pct")
        lines.append(f"│  Throughput")
        lines.append(f"│    Aplicação  : {ak:.1f} KB/s  (± {r.get('app_throughput_kbps_std', 0):.1f})" if ak else "│    Aplicação  : N/A")
        lines.append(f"│    Rede       : {nk:.1f} KB/s  (± {r.get('net_throughput_kbps_std', 0):.1f})" if nk else "│    Rede       : N/A")
        lines.append(f"│    Diferença  : {dk:+.2f}%  ({'OK' if dk and abs(dk) < 15 else 'VERIFICAR' if dk else 'N/A'})" if dk is not None else "│    Diferença  : N/A")

        lines.append(f"└{'─'*54}")
        lines.append("")

    lines.append("LEGENDA")
    lines.append("  Overhead    : bytes_rede - bytes_app / bytes_app × 100")
    lines.append("                Esperado: 1–4% (headers Ethernet/IP/TCP ou UDP)")
    lines.append("  Diferença   : (valor_app - valor_rede) / valor_rede × 100")
    lines.append("                OK se < 10–15% (diferença de ponto de medição)")
    lines.append("  VERIFICAR   : diferença acima do esperado — revisar captura")

    Path(out_path).write_text("\n".join(lines))
    print(f"  → {out_path}")


# ── Gráficos ──────────────────────────────────────────────────────────────────

def _style(ax, title, xlabel, ylabel):
    ax.set_title(title, fontsize=12, fontweight="bold", pad=8)
    ax.set_xlabel(xlabel, fontsize=10)
    ax.set_ylabel(ylabel, fontsize=10)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(axis="y", linestyle="--", alpha=0.35)
    ax.legend(fontsize=9)


def plot_comparison_bar(rows: list[dict], out: str) -> None:
    """Throughput aplicação vs rede, agrupado por cenário, separado por protocolo."""
    import matplotlib.pyplot as plt
    import numpy as np

    fig, axes = plt.subplots(1, len(PROTOS), figsize=(13, 5), sharey=False)
    if len(PROTOS) == 1:
        axes = [axes]

    for ax, proto in zip(axes, PROTOS):
        sub = [r for r in rows if r["proto"] == proto]
        if not sub:
            ax.set_visible(False)
            continue

        scens  = [r["scenario"] for r in sub]
        app_v  = [r.get("app_throughput_kbps_mean") or 0 for r in sub]
        net_v  = [r.get("net_throughput_kbps_mean") or 0 for r in sub]
        app_e  = [r.get("app_throughput_kbps_std")  or 0 for r in sub]
        net_e  = [r.get("net_throughput_kbps_std")  or 0 for r in sub]

        x = np.arange(len(scens))
        w = 0.35
        ax.bar(x - w/2, app_v, w, label="Aplicação (JSON)",
               color=COLORS["app"][proto], alpha=0.85,
               yerr=app_e, capsize=5, error_kw=dict(elinewidth=1.5))
        ax.bar(x + w/2, net_v, w, label="Rede (pcap)",
               color=COLORS["net"][proto], alpha=0.85,
               yerr=net_e, capsize=5, error_kw=dict(elinewidth=1.5))

        ax.set_xticks(x)
        ax.set_xticklabels([SCENARIO_LABELS.get(s, s) for s in scens], fontsize=8)
        _style(ax, f"Throughput — {proto.upper()}", "Cenário", "KB/s")

    fig.suptitle("Throughput: Aplicação vs Rede", fontsize=13, fontweight="bold")
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)
    print(f"  → {out}")


def plot_volume(rows: list[dict], out: str) -> None:
    """Volume de dados aplicação vs rede."""
    import matplotlib.pyplot as plt
    import numpy as np

    fig, axes = plt.subplots(1, len(PROTOS), figsize=(13, 5), sharey=False)
    if len(PROTOS) == 1:
        axes = [axes]

    for ax, proto in zip(axes, PROTOS):
        sub = [r for r in rows if r["proto"] == proto]
        if not sub:
            ax.set_visible(False)
            continue

        scens = [r["scenario"] for r in sub]
        app_v = [(r.get("app_size_bytes_mean") or 0) / 1024 for r in sub]
        net_v = [(r.get("net_bytes_total_mean") or 0) / 1024 for r in sub]
        ohs   = [r.get("overhead_pct") or 0 for r in sub]

        x = np.arange(len(scens))
        w = 0.35
        bars_app = ax.bar(x - w/2, app_v, w, label="Aplicação (payload)",
                          color=COLORS["app"][proto], alpha=0.85)
        bars_net = ax.bar(x + w/2, net_v, w, label="Rede (frames completos)",
                          color=COLORS["net"][proto], alpha=0.85)

        # Anota overhead
        for bar, oh in zip(bars_net, ohs):
            ax.text(bar.get_x() + bar.get_width() / 2,
                    bar.get_height() + 1,
                    f"+{oh:.1f}%", ha="center", va="bottom", fontsize=8, color="#555")

        ax.set_xticks(x)
        ax.set_xticklabels([SCENARIO_LABELS.get(s, s) for s in scens], fontsize=8)
        _style(ax, f"Volume de Dados — {proto.upper()}", "Cenário", "KB")

    fig.suptitle("Volume: Aplicação vs Rede (overhead = headers IP/TCP/UDP)", fontsize=12, fontweight="bold")
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)
    print(f"  → {out}")


def plot_time(rows: list[dict], out: str) -> None:
    """Tempo de transferência aplicação vs rede."""
    import matplotlib.pyplot as plt
    import numpy as np

    fig, axes = plt.subplots(1, len(PROTOS), figsize=(13, 5), sharey=False)
    if len(PROTOS) == 1:
        axes = [axes]

    for ax, proto in zip(axes, PROTOS):
        sub = [r for r in rows if r["proto"] == proto]
        if not sub:
            ax.set_visible(False)
            continue

        scens = [r["scenario"] for r in sub]
        app_v = [r.get("app_elapsed_s_mean") or 0 for r in sub]
        net_v = [r.get("net_duration_s_mean") or 0 for r in sub]
        app_e = [r.get("app_elapsed_s_std")   or 0 for r in sub]
        net_e = [r.get("net_duration_s_std")   or 0 for r in sub]

        x = np.arange(len(scens))
        w = 0.35
        ax.bar(x - w/2, app_v, w, label="Aplicação (elapsed)",
               color=COLORS["app"][proto], alpha=0.85,
               yerr=app_e, capsize=5, error_kw=dict(elinewidth=1.5))
        ax.bar(x + w/2, net_v, w, label="Rede (duration)",
               color=COLORS["net"][proto], alpha=0.85,
               yerr=net_e, capsize=5, error_kw=dict(elinewidth=1.5))

        ax.set_xticks(x)
        ax.set_xticklabels([SCENARIO_LABELS.get(s, s) for s in scens], fontsize=8)
        _style(ax, f"Tempo — {proto.upper()}", "Cenário", "Segundos")

    fig.suptitle("Tempo de Transferência: Aplicação vs Rede", fontsize=13, fontweight="bold")
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)
    print(f"  → {out}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(description="Compara JSON da aplicação com CSV do tshark")
    ap.add_argument("--logsdir", default="logs",         help="Diretório com os .json e .csv")
    ap.add_argument("--outdir",  default="analysis/out", help="Diretório de saída")
    args = ap.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    pairs = find_pairs(args.logsdir)
    if not pairs:
        print("Nenhum par JSON + conversations.csv encontrado.")
        print(f"Verifique se existem arquivos como logs/A_tcp.json e logs/A_tcp_conversations.csv")
        return

    print(f"\nPares encontrados: {len(pairs)}")

    PORT = {"tcp": 5000, "rudp": 5001}
    rows = []

    for p in pairs:
        scenario = p["scenario"]
        proto    = p["proto"]
        print(f"\n  Cenário {scenario} | {proto.upper()}")

        df_json = load_json(p["json"])
        df_conv = load_conversations_csv(p["conv_csv"])

        am = app_metrics(df_json)
        nm = net_metrics(df_conv, proto, PORT[proto])

        row = {"scenario": scenario, "proto": proto}
        row.update(am)
        row.update(nm)

        # Deltas
        row["overhead_pct"]       = overhead_pct(am["app_size_bytes_mean"], nm.get("net_bytes_total_mean"))
        row["delta_time_pct"]     = delta_pct(am["app_elapsed_s_mean"],     nm.get("net_duration_s_mean"))
        row["delta_throughput_pct"] = delta_pct(am["app_throughput_kbps_mean"], nm.get("net_throughput_kbps_mean"))

        rows.append(row)

        # Print rápido no terminal
        print(f"    Volume  — app: {am['app_size_bytes_mean']/1024:.1f} KB  "
              f"rede: {(nm.get('net_bytes_total_mean') or 0)/1024:.1f} KB  "
              f"overhead: {row['overhead_pct']}%")
        print(f"    Tempo   — app: {am['app_elapsed_s_mean']:.4f} s  "
              f"rede: {nm.get('net_duration_s_mean', 0):.4f} s  "
              f"Δ: {row['delta_time_pct']}%")
        print(f"    Throughput — app: {am['app_throughput_kbps_mean']:.1f} KB/s  "
              f"rede: {nm.get('net_throughput_kbps_mean', 0):.1f} KB/s  "
              f"Δ: {row['delta_throughput_pct']}%")

    # ── CSV consolidado ───────────────────────────────────────────────────────
    print("\nSalvando saídas…")
    summary_df = pd.DataFrame(rows)
    csv_path = outdir / "comparison_summary.csv"
    summary_df.to_csv(csv_path, index=False)
    print(f"  → {csv_path}")

    # ── Relatório texto ───────────────────────────────────────────────────────
    write_report(rows, str(outdir / "comparison_report.txt"))

    # ── Gráficos ──────────────────────────────────────────────────────────────
    plot_comparison_bar(rows, str(outdir / "07_comparison_throughput.png"))
    plot_volume        (rows, str(outdir / "08_comparison_volume.png"))
    plot_time          (rows, str(outdir / "09_comparison_time.png"))

    print(f"\nPronto. Arquivos em: {outdir}/")


if __name__ == "__main__":
    main()