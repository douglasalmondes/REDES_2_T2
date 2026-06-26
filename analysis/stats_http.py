"""analysis/stats_http.py — Estatísticas e gráficos dos testes de
DNS + Miniservidor HTTP/1.1 (sobre TCP e R-UDP), conforme exigido na
Terceira Avaliação.

Uso:
  python3 analysis/stats_http.py --inputs "logs/*_http_*.json" --outdir analysis/out_http
  python3 analysis/stats_http.py --inputs "logs/*_http_*.json" --outdir analysis/out_http \
      --rudp-file-log logs_trabalho1/A_rudp.json   # opcional, para comparar overhead de cabeçalho

Espera logs no formato gerado por src/http_client.py (run_multiple), com um
arquivo JSON por combinação (cenário, transporte, tamanho de arquivo):
  logs/A_http_tcp_file_100kb.json
  logs/A_http_rudp_file_1mb.json
  ...

Saídas:
  - summary.csv                          — estatísticas agregadas (runs, mín/méd/máx/DP)
  - 01_throughput_by_scenario_size.png   — taxa de transferência: 3 cenários x TCP/R-UDP x tamanho
  - 02_dns_time_by_scenario.png          — tempo de resolução DNS por cenário (impacto da perda)
  - 03_http_vs_dns_time.png              — tempo HTTP vs tempo DNS (overhead relativo)
  - 04_header_overhead.png               — overhead do cabeçalho HTTP vs protocolo textual (trabalho 1)
  - 05_retrans_by_scenario.png           — retransmissões médias do R-UDP por cenário
  - 06_throughput_heatmap.png            — heatmap throughput médio (transporte x cenário), por tamanho
"""

import argparse
import glob
import json
import os
import re
from pathlib import Path

import pandas as pd

SCENARIO_ORDER = ["A", "B", "C"]
SCENARIO_LABELS = {"A": "A\n(0% loss/10ms)", "B": "B\n(5% loss/50ms)", "C": "C\n(10% loss/100ms)"}
COLORS = {"TCP": "#2196F3", "RUDP": "#FF5722"}
FILE_ORDER = ["file_100kb", "file_1mb", "file_10mb"]
FILE_LABELS = {"file_100kb": "100 kB", "file_1mb": "1 MB", "file_10mb": "10 MB"}

# Overhead de cabeçalho do protocolo textual customizado do Trabalho 1
# (linha de metadados JSON: {"filename":..., "size":..., "auth": <64 chars sha256>})
# usado como baseline de comparação na Pergunta Obrigatória 2.
LEGACY_HEADER_EXAMPLE_BYTES = len(
    '{"filename": "test.bin", "size": 1048576, "auth": "' + "a" * 64 + '"}\n'
)


def _filename_tag(path: str) -> tuple[str, str, str]:
    """Extrai (scenario, transport, file_tag) de um nome tipo
    'A_http_tcp_file_100kb.json'."""
    base = os.path.basename(path).replace(".json", "")
    m = re.match(r"^([ABC])_http_(tcp|rudp)_(file_\w+)$", base)
    if not m:
        return ("?", "?", base)
    return (m.group(1), m.group(2), m.group(3))


def load_logs(paths: list[str]) -> pd.DataFrame:
    rows = []
    for p in paths:
        scenario, transport, file_tag = _filename_tag(p)
        with open(p) as f:
            data = json.load(f) or []
        for row in data:
            row = dict(row)
            row.setdefault("scenario", scenario)
            row.setdefault("transport", transport.upper())
            row["file_tag"] = file_tag
            row.setdefault("retransmissions", 0)
            row.setdefault("timeouts", 0)
            row.setdefault("dns_elapsed_s", 0)
            row.setdefault("http_elapsed_s", row.get("elapsed_s", 0))
            rows.append(row)
    return pd.DataFrame(rows) if rows else pd.DataFrame()


def summarize(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df
    agg = df.groupby(["transport", "scenario", "file_tag"]).agg(
        runs=("throughput_bps", "count"),
        min_bps=("throughput_bps", "min"),
        mean_bps=("throughput_bps", "mean"),
        max_bps=("throughput_bps", "max"),
        std_bps=("throughput_bps", "std"),
        mean_total_s=("total_elapsed_s", "mean"),
        mean_dns_ms=("dns_elapsed_s", lambda s: s.mean() * 1000),
        std_dns_ms=("dns_elapsed_s", lambda s: s.std() * 1000),
        mean_http_s=("http_elapsed_s", "mean"),
        mean_retrans=("retransmissions", "mean"),
        mean_timeouts=("timeouts", "mean"),
        error_rate=("status", lambda s: (s != 200).mean()),
    ).reset_index()
    for col in ["min_bps", "mean_bps", "max_bps", "std_bps"]:
        agg[col.replace("_bps", "_kBps")] = agg[col] / 1024
    return agg


def _style(ax, title, xlabel, ylabel):
    ax.set_title(title, fontsize=13, fontweight="bold", pad=10)
    ax.set_xlabel(xlabel, fontsize=11)
    ax.set_ylabel(ylabel, fontsize=11)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(axis="y", linestyle="--", alpha=0.4)


# ── Plot 1: Throughput por cenário, transporte e tamanho de arquivo ──────────

def plot_throughput_by_scenario_size(summary: pd.DataFrame, out: str) -> None:
    import matplotlib.pyplot as plt
    import numpy as np

    files = [f for f in FILE_ORDER if f in summary["file_tag"].unique()]
    n = len(files)
    fig, axes = plt.subplots(1, n, figsize=(6 * n, 5), sharey=False)
    if n == 1:
        axes = [axes]

    for ax, file_tag in zip(axes, files):
        sub_file = summary[summary["file_tag"] == file_tag]
        scenarios = [s for s in SCENARIO_ORDER if s in sub_file["scenario"].unique()]
        x = np.arange(len(scenarios))
        width = 0.35
        for i, proto in enumerate(["TCP", "RUDP"]):
            sub = sub_file[sub_file["transport"] == proto].set_index("scenario")
            means = [sub.loc[s, "mean_kBps"] if s in sub.index else 0 for s in scenarios]
            stds = [sub.loc[s, "std_bps"] / 1024 if s in sub.index else 0 for s in scenarios]
            offset = (i - 0.5) * width
            ax.bar(x + offset, means, width, label=proto, color=COLORS[proto],
                   alpha=0.85, yerr=stds, capsize=5, error_kw=dict(elinewidth=1.2))
        ax.set_xticks(x)
        ax.set_xticklabels([SCENARIO_LABELS.get(s, s) for s in scenarios])
        _style(ax, f"Arquivo {FILE_LABELS.get(file_tag, file_tag)}", "Cenário", "Throughput (KB/s)")
        ax.legend(fontsize=9)

    fig.suptitle("Taxa de Transferência — TCP vs R-UDP por Cenário e Tamanho de Arquivo (com DNS)",
                  fontsize=14, fontweight="bold")
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)
    print(f"  → {out}")


# ── Plot 2: Tempo de resolução DNS por cenário ────────────────────────────────

def plot_dns_time(summary: pd.DataFrame, out: str) -> None:
    import matplotlib.pyplot as plt
    import numpy as np

    # DNS não depende do tamanho do arquivo nem do transporte HTTP escolhido
    # (é sempre UDP nativo na porta 5300); agregamos por cenário apenas.
    dns_agg = summary.groupby("scenario").agg(
        mean_dns_ms=("mean_dns_ms", "mean"),
        std_dns_ms=("std_dns_ms", "mean"),
    ).reset_index()

    scenarios = [s for s in SCENARIO_ORDER if s in dns_agg["scenario"].unique()]
    dns_agg = dns_agg.set_index("scenario")
    means = [dns_agg.loc[s, "mean_dns_ms"] if s in dns_agg.index else 0 for s in scenarios]
    stds = [dns_agg.loc[s, "std_dns_ms"] if s in dns_agg.index else 0 for s in scenarios]

    fig, ax = plt.subplots(figsize=(7, 5))
    x = np.arange(len(scenarios))
    bars = ax.bar(x, means, width=0.5, color="#4CAF50", alpha=0.85,
                   yerr=stds, capsize=6, error_kw=dict(elinewidth=1.5))
    for bar, m in zip(bars, means):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(),
                f"{m:.1f} ms", ha="center", va="bottom", fontsize=10)

    ax.set_xticks(x)
    ax.set_xticklabels([SCENARIO_LABELS.get(s, s) for s in scenarios])
    _style(ax, "Tempo Médio de Resolução DNS por Cenário\n(UDP nativo, sem retransmissão de transporte)",
           "Cenário de Rede", "Tempo (ms)")
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)
    print(f"  → {out}")


# ── Plot 3: Tempo HTTP vs tempo DNS (proporção do overhead) ──────────────────

def plot_http_vs_dns(summary: pd.DataFrame, out: str) -> None:
    import matplotlib.pyplot as plt
    import numpy as np

    files = [f for f in FILE_ORDER if f in summary["file_tag"].unique()]
    scenarios = [s for s in SCENARIO_ORDER if s in summary["scenario"].unique()]

    fig, axes = plt.subplots(1, len(files), figsize=(5.5 * len(files), 5), sharey=True)
    if len(files) == 1:
        axes = [axes]

    for ax, file_tag in zip(axes, files):
        sub_file = summary[(summary["file_tag"] == file_tag) & (summary["transport"] == "TCP")]
        sub_file = sub_file.set_index("scenario")
        dns_ms = [sub_file.loc[s, "mean_dns_ms"] if s in sub_file.index else 0 for s in scenarios]
        http_ms = [sub_file.loc[s, "mean_http_s"] * 1000 if s in sub_file.index else 0 for s in scenarios]

        x = np.arange(len(scenarios))
        ax.bar(x, dns_ms, width=0.5, label="Tempo DNS", color="#4CAF50", alpha=0.85)
        ax.bar(x, http_ms, width=0.5, bottom=dns_ms, label="Tempo HTTP (download)", color="#2196F3", alpha=0.85)
        ax.set_xticks(x)
        ax.set_xticklabels([SCENARIO_LABELS.get(s, s) for s in scenarios])
        _style(ax, f"{FILE_LABELS.get(file_tag, file_tag)} (TCP)", "Cenário", "Tempo (ms)")
        ax.legend(fontsize=9)

    fig.suptitle("Composição do Tempo Total: DNS vs Download HTTP", fontsize=14, fontweight="bold")
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)
    print(f"  → {out}")


# ── Plot 4: Overhead de cabeçalho HTTP vs protocolo textual (Trabalho 1) ─────

def plot_header_overhead(summary: pd.DataFrame, out: str, legacy_header_bytes: int) -> None:
    import matplotlib.pyplot as plt

    # Overhead aproximado do cabeçalho HTTP/1.1 simplificado deste trabalho:
    # status-line + Content-Type + Content-Length + X-Custom-Auth(64) + Connection
    # Calculado de forma representativa (varia pouco entre respostas 200).
    http_header_example = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: 1048576\r\n"
        f"X-Custom-Auth: {'a' * 64}\r\n"
        "Connection: close\r\n\r\n"
    )
    http_header_bytes = len(http_header_example.encode())

    labels = ["Protocolo Textual\n(Trabalho 1)\nmetadado JSON + auth", "HTTP/1.1 Simplificado\n(Trabalho 2)\nstatus+headers+auth"]
    values = [legacy_header_bytes, http_header_bytes]
    colors = ["#9E9E9E", "#FF9800"]

    fig, ax = plt.subplots(figsize=(8.5, 5.5))
    bars = ax.bar(labels, values, color=colors, alpha=0.85, width=0.5)
    for bar, v in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(),
                f"{v} bytes", ha="center", va="bottom", fontsize=11, fontweight="bold")

    _style(ax, "Overhead de Cabeçalho:\nProtocolo Textual (T1) vs HTTP/1.1 Simplificado (T2)",
           "", "Tamanho do cabeçalho (bytes)")
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)
    print(f"  → {out}")
    print(f"  [INFO] Overhead textual (T1) = {legacy_header_bytes} bytes | "
          f"Overhead HTTP/1.1 (T2) = {http_header_bytes} bytes | "
          f"Diferença = {http_header_bytes - legacy_header_bytes} bytes")


# ── Plot 5: Retransmissões médias do R-UDP por cenário ────────────────────────

def plot_retrans(summary: pd.DataFrame, out: str) -> None:
    import matplotlib.pyplot as plt
    import numpy as np

    rudp = summary[summary["transport"] == "RUDP"].copy()
    if rudp.empty:
        print("  [AVISO] Sem dados R-UDP para plot de retransmissões.")
        return

    files = [f for f in FILE_ORDER if f in rudp["file_tag"].unique()]
    scenarios = [s for s in SCENARIO_ORDER if s in rudp["scenario"].unique()]
    x = np.arange(len(scenarios))
    width = 0.25

    fig, ax = plt.subplots(figsize=(9, 5))
    for i, file_tag in enumerate(files):
        sub = rudp[rudp["file_tag"] == file_tag].set_index("scenario")
        vals = [sub.loc[s, "mean_retrans"] if s in sub.index else 0 for s in scenarios]
        offset = (i - len(files) / 2 + 0.5) * width
        ax.bar(x + offset, vals, width, label=FILE_LABELS.get(file_tag, file_tag), alpha=0.85)

    ax.set_xticks(x)
    ax.set_xticklabels([SCENARIO_LABELS.get(s, s) for s in scenarios])
    _style(ax, "R-UDP (resposta HTTP) — Média de Retransmissões por Cenário e Tamanho",
           "Cenário de Rede", "Retransmissões médias")
    ax.legend(fontsize=9, title="Arquivo")
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)
    print(f"  → {out}")


# ── Plot 6: Heatmap throughput médio (transporte x cenário) por tamanho ──────

def plot_heatmap(summary: pd.DataFrame, out: str) -> None:
    import matplotlib.pyplot as plt

    files = [f for f in FILE_ORDER if f in summary["file_tag"].unique()]
    fig, axes = plt.subplots(1, len(files), figsize=(5 * len(files), 3.5))
    if len(files) == 1:
        axes = [axes]

    for ax, file_tag in zip(axes, files):
        sub = summary[summary["file_tag"] == file_tag]
        pivot = sub.pivot(index="transport", columns="scenario", values="mean_kBps")
        pivot = pivot.reindex(columns=[s for s in SCENARIO_ORDER if s in pivot.columns])

        im = ax.imshow(pivot.values, cmap="YlOrRd", aspect="auto")
        ax.set_xticks(range(len(pivot.columns)))
        ax.set_xticklabels([SCENARIO_LABELS.get(s, s) for s in pivot.columns], fontsize=8)
        ax.set_yticks(range(len(pivot.index)))
        ax.set_yticklabels(pivot.index)
        ax.set_title(FILE_LABELS.get(file_tag, file_tag), fontsize=11, fontweight="bold")
        for i in range(len(pivot.index)):
            for j in range(len(pivot.columns)):
                val = pivot.values[i, j]
                if not pd.isna(val):
                    ax.text(j, i, f"{val:.0f}", ha="center", va="center",
                            color="black", fontsize=9, fontweight="bold")

    fig.suptitle("Heatmap — Throughput Médio (KB/s)", fontsize=13, fontweight="bold")
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)
    print(f"  → {out}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Análise estatística dos testes DNS + HTTP/1.1")
    ap.add_argument("--inputs", nargs="+", required=True,
                     help='Padrões glob (ex: "logs/*_http_*.json")')
    ap.add_argument("--outdir", default="analysis/out_http")
    ap.add_argument("--legacy-header-bytes", type=int, default=LEGACY_HEADER_EXAMPLE_BYTES,
                     help="Overhead (bytes) do cabeçalho textual do Trabalho 1, para comparação")
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
    print(summary[["transport", "scenario", "file_tag", "runs", "mean_kBps", "std_bps", "mean_dns_ms", "error_rate"]]
          .to_string(index=False))

    print("\nGerando gráficos…")
    plot_throughput_by_scenario_size(summary, str(outdir / "01_throughput_by_scenario_size.png"))
    plot_dns_time(summary, str(outdir / "02_dns_time_by_scenario.png"))
    plot_http_vs_dns(summary, str(outdir / "03_http_vs_dns_time.png"))
    plot_header_overhead(summary, str(outdir / "04_header_overhead.png"), args.legacy_header_bytes)
    plot_retrans(summary, str(outdir / "05_retrans_by_scenario.png"))
    plot_heatmap(summary, str(outdir / "06_throughput_heatmap.png"))

    print(f"\nPronto. Arquivos em: {outdir}/")


if __name__ == "__main__":
    main()
