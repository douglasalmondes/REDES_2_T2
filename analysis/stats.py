"""analysis/stats.py — Estatísticas de throughput a partir dos logs JSON.

Uso:
  python3 analysis/stats.py --inputs logs/*.json --outdir analysis/out

Saídas:
  - summary.csv
  - 01_boxplot_throughput.png       — distribuição por protocolo/cenário
  - 02_barplot_mean_std.png         — média ± desvio padrão (requisito avaliação)
  - 03_lineplot_scenarios.png       — evolução TCP vs R-UDP por cenário
  - 04_barplot_retrans_nacks.png    — retransmissões e NACKs (só R-UDP)
  - 05_heatmap_mean_throughput.png  — heatmap protocolo × cenário
  - 06_barplot_elapsed.png          — tempo médio de transferência
"""

import argparse
import glob
import json
import os
from pathlib import Path

import pandas as pd



def load_logs(paths: list[str]) -> pd.DataFrame:
    rows = []
    for p in paths:
        with open(p, "r") as f:
            data = json.load(f) or []
        for row in data:
            row = dict(row)
            row.setdefault("source_log", os.path.basename(p))
            row.setdefault("scenario", "")
            row.setdefault("protocol", "")
            row.setdefault("retransmissions", 0)
            row.setdefault("timeouts", 0)
            row.setdefault("nacks", 0)
            rows.append(row)
    return pd.DataFrame(rows) if rows else pd.DataFrame()


def summarize(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df
    agg = df.groupby(["protocol", "scenario"]).agg(
        runs=("throughput_bps", "count"),
        min_bps=("throughput_bps", "min"),
        mean_bps=("throughput_bps", "mean"),
        max_bps=("throughput_bps", "max"),
        std_bps=("throughput_bps", "std"),
        mean_elapsed_s=("elapsed_s", "mean"),
        mean_retrans=("retransmissions", "mean"),
        mean_timeouts=("timeouts", "mean"),
        mean_nacks=("nacks", "mean"),
    ).reset_index()
    for col in ["min_bps", "mean_bps", "max_bps", "std_bps"]:
        agg[col.replace("_bps", "_kBps")] = agg[col] / 1024
    return agg



COLORS = {"TCP": "#2196F3", "RUDP": "#FF5722"}
SCENARIO_ORDER = ["A", "B", "C"]
SCENARIO_LABELS = {"A": "A\n(0% loss / 10ms)", "B": "B\n(5% loss / 50ms)", "C": "C\n(10% loss / 100ms)"}


def _style(ax, title, xlabel, ylabel):
    ax.set_title(title, fontsize=13, fontweight="bold", pad=10)
    ax.set_xlabel(xlabel, fontsize=11)
    ax.set_ylabel(ylabel, fontsize=11)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    ax.legend(fontsize=10)


# ── Plot 1: Boxplot ────────────────────────────────────────────────────────────

def plot_boxplot(df: pd.DataFrame, out: str) -> None:
    import matplotlib.pyplot as plt

    df = df.copy()
    df["label"] = df["protocol"] + "-" + df["scenario"]
    labels = sorted(df["label"].unique())
    data = [df.loc[df["label"] == l, "throughput_bps"].dropna().values / 1024 for l in labels]
    colors = [COLORS.get(l.split("-")[0], "#999") for l in labels]

    fig, ax = plt.subplots(figsize=(11, 5))
    bp = ax.boxplot(data, labels=labels, showmeans=True, patch_artist=True,
                    meanprops=dict(marker="D", markerfacecolor="black", markersize=5))
    for patch, color in zip(bp["boxes"], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.6)

    _style(ax, "Distribuição de Throughput por Protocolo/Cenário",
           "Protocolo – Cenário", "Throughput (KB/s)")
    ax.get_legend_handles_labels()
    # legenda manual
    from matplotlib.patches import Patch
    handles = [Patch(facecolor=c, alpha=0.6, label=p) for p, c in COLORS.items()]
    ax.legend(handles=handles, fontsize=10)
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)
    print(f"  → {out}")


# ── Plot 2: Barras Média ± Desvio Padrão (requisito principal) ────────────────

def plot_mean_std(df: pd.DataFrame, summary: pd.DataFrame, out: str) -> None:
    import matplotlib.pyplot as plt
    import numpy as np

    protocols = sorted(summary["protocol"].unique())
    scenarios = [s for s in SCENARIO_ORDER if s in summary["scenario"].unique()]
    x = np.arange(len(scenarios))
    width = 0.35

    fig, ax = plt.subplots(figsize=(10, 5))
    for i, proto in enumerate(protocols):
        sub = summary[summary["protocol"] == proto].set_index("scenario")
        means = [sub.loc[s, "mean_kBps"] if s in sub.index else 0 for s in scenarios]
        stds  = [sub.loc[s, "std_bps"] / 1024 if s in sub.index else 0 for s in scenarios]
        offset = (i - len(protocols) / 2 + 0.5) * width
        bars = ax.bar(x + offset, means, width, label=proto,
                      color=COLORS.get(proto, "#999"), alpha=0.8,
                      yerr=stds, capsize=6, error_kw=dict(elinewidth=1.5, ecolor="black"))
        # Anotação do valor em cima de cada barra
        for bar, m, s in zip(bars, means, stds):
            ax.text(bar.get_x() + bar.get_width() / 2,
                    bar.get_height() + s + 1,
                    f"{m:.0f}", ha="center", va="bottom", fontsize=8)

    ax.set_xticks(x)
    ax.set_xticklabels([SCENARIO_LABELS.get(s, s) for s in scenarios])
    _style(ax, "Throughput Médio ± Desvio Padrão — TCP vs R-UDP por Cenário",
           "Cenário de Rede", "Throughput (KB/s)")
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)
    print(f"  → {out}")


# ── Plot 3: Linha — evolução por cenário ──────────────────────────────────────

def plot_line_scenarios(summary: pd.DataFrame, out: str) -> None:
    import matplotlib.pyplot as plt
    import numpy as np

    scenarios = [s for s in SCENARIO_ORDER if s in summary["scenario"].unique()]
    fig, ax = plt.subplots(figsize=(8, 5))

    for proto in sorted(summary["protocol"].unique()):
        sub = summary[summary["protocol"] == proto].set_index("scenario")
        means = [sub.loc[s, "mean_kBps"] if s in sub.index else np.nan for s in scenarios]
        stds  = [sub.loc[s, "std_bps"] / 1024 if s in sub.index else 0 for s in scenarios]
        ax.errorbar(scenarios, means, yerr=stds, label=proto,
                    color=COLORS.get(proto, "#999"),
                    marker="o", linewidth=2, capsize=5, markersize=7)

    _style(ax, "Evolução do Throughput por Cenário — TCP vs R-UDP",
           "Cenário (degradação crescente →)", "Throughput Médio (KB/s)")
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)
    print(f"  → {out}")


# ── Plot 4: Retransmissões e NACKs (R-UDP) ───────────────────────────────────

def plot_retrans(summary: pd.DataFrame, out: str) -> None:
    import matplotlib.pyplot as plt
    import numpy as np

    rudp = summary[summary["protocol"].str.upper() == "RUDP"].copy()
    if rudp.empty:
        print("  [AVISO] Sem dados R-UDP para plot de retransmissões.")
        return

    scenarios = [s for s in SCENARIO_ORDER if s in rudp["scenario"].unique()]
    x = np.arange(len(scenarios))
    width = 0.3

    fig, ax = plt.subplots(figsize=(8, 5))
    sub = rudp.set_index("scenario")
    retrans = [sub.loc[s, "mean_retrans"] if s in sub.index else 0 for s in scenarios]
    nacks   = [sub.loc[s, "mean_nacks"]   if s in sub.index else 0 for s in scenarios]

    ax.bar(x - width / 2, retrans, width, label="Retransmissões", color="#FF5722", alpha=0.8)
    ax.bar(x + width / 2, nacks,   width, label="NACKs",          color="#FFC107", alpha=0.8)

    ax.set_xticks(x)
    ax.set_xticklabels([SCENARIO_LABELS.get(s, s) for s in scenarios])
    _style(ax, "R-UDP — Média de Retransmissões e NACKs por Cenário",
           "Cenário de Rede", "Quantidade média por transferência")
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)
    print(f"  → {out}")


# ── Plot 5: Heatmap throughput ────────────────────────────────────────────────

def plot_heatmap(summary: pd.DataFrame, out: str) -> None:
    import matplotlib.pyplot as plt

    pivot = summary.pivot(index="protocol", columns="scenario", values="mean_kBps")
    pivot = pivot.reindex(columns=[s for s in SCENARIO_ORDER if s in pivot.columns])

    fig, ax = plt.subplots(figsize=(7, 3.5))
    im = ax.imshow(pivot.values, cmap="YlOrRd", aspect="auto")
    ax.set_xticks(range(len(pivot.columns)))
    ax.set_xticklabels([SCENARIO_LABELS.get(s, s) for s in pivot.columns])
    ax.set_yticks(range(len(pivot.index)))
    ax.set_yticklabels(pivot.index)
    ax.set_title("Heatmap — Throughput Médio (KB/s)", fontsize=13, fontweight="bold")
    plt.colorbar(im, ax=ax, label="KB/s")

    for i in range(len(pivot.index)):
        for j in range(len(pivot.columns)):
            val = pivot.values[i, j]
            if not pd.isna(val):
                ax.text(j, i, f"{val:.0f}", ha="center", va="center",
                        color="black", fontsize=11, fontweight="bold")
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)
    print(f"  → {out}")


# ── Plot 6: Tempo médio de transferência ──────────────────────────────────────

def plot_elapsed(summary: pd.DataFrame, out: str) -> None:
    import matplotlib.pyplot as plt
    import numpy as np

    protocols = sorted(summary["protocol"].unique())
    scenarios = [s for s in SCENARIO_ORDER if s in summary["scenario"].unique()]
    x = np.arange(len(scenarios))
    width = 0.35

    fig, ax = plt.subplots(figsize=(9, 5))
    for i, proto in enumerate(protocols):
        sub = summary[summary["protocol"] == proto].set_index("scenario")
        elapsed = [sub.loc[s, "mean_elapsed_s"] if s in sub.index else 0 for s in scenarios]
        offset = (i - len(protocols) / 2 + 0.5) * width
        bars = ax.bar(x + offset, elapsed, width, label=proto,
                      color=COLORS.get(proto, "#999"), alpha=0.8)
        for bar, v in zip(bars, elapsed):
            ax.text(bar.get_x() + bar.get_width() / 2,
                    bar.get_height() + 0.05,
                    f"{v:.1f}s", ha="center", va="bottom", fontsize=8)

    ax.set_xticks(x)
    ax.set_xticklabels([SCENARIO_LABELS.get(s, s) for s in scenarios])
    _style(ax, "Tempo Médio de Transferência — TCP vs R-UDP por Cenário",
           "Cenário de Rede", "Tempo (s)")
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)
    print(f"  → {out}")



def main() -> None:
    ap = argparse.ArgumentParser(description="Análise estatística dos logs de throughput")
    ap.add_argument("--inputs", nargs="+", required=True, help="Arquivos JSON (ex: logs/*.json)")
    ap.add_argument("--outdir", default="analysis/out", help="Diretório de saída")
    args = ap.parse_args()

    expanded = sorted(set(p for pat in args.inputs for p in glob.glob(pat)))
    if not expanded:
        print("Nenhum arquivo encontrado.")
        return

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    print(f"\nCarregando {len(expanded)} arquivo(s)…")
    df = load_logs(expanded)
    if df.empty:
        print("Nenhum dado encontrado.")
        return

    summary = summarize(df)
    summary_path = outdir / "summary.csv"
    summary.to_csv(summary_path, index=False)
    print(f"  → {summary_path}")
    print(summary[["protocol", "scenario", "runs", "mean_kBps", "std_bps"]].to_string(index=False))

    print("\nGerando gráficos…")
    plot_boxplot     (df,      str(outdir / "01_boxplot_throughput.png"))
    plot_mean_std    (df, summary, str(outdir / "02_barplot_mean_std.png"))
    plot_line_scenarios(summary,   str(outdir / "03_lineplot_scenarios.png"))
    plot_retrans     (summary,     str(outdir / "04_barplot_retrans_nacks.png"))
    plot_heatmap     (summary,     str(outdir / "05_heatmap_mean_throughput.png"))
    plot_elapsed     (summary,     str(outdir / "06_barplot_elapsed.png"))

    print(f"\nPronto. Arquivos em: {outdir}/")


if __name__ == "__main__":
    main()