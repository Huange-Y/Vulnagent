"""Batch firmware vulnerability analysis — fully automated 0day hunting pipeline.

Scans firmware/ for images, runs vulnagent against each, and produces
structured output in output/<firmware_name>/:

  output/<name>/
    report.md          # Full markdown report (PoC + CVSS + Remediation)
    findings.json      # Machine-readable finding list with CWE/CVSS
    summary.json       # Run metrics (tokens, tools, iterations)
    poc/               # Standalone PoC Python scripts

Usage:
    python -m vulnagent.batch_runner          # Scan firmware/
    python -m vulnagent.batch_runner --dir firmware/ --output output/
    python -m vulnagent.batch_runner --single firmware/test.img
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

FIRMWARE_EXTS = {
    ".img", ".bin", ".fw", ".rom", ".trx", ".chk", ".ubi",
    ".squashfs", ".cpio", ".iso", ".ubi", ".ubifs", ".jffs2",
    ".zip", ".tar", ".gz", ".xz", ".lzma", ".lz4", ".7z",
    ".upgrade", ".web", ".stk", ".nbg",
}


def _find_firmware_files(directory: str | Path) -> list[Path]:
    """Find all firmware files in a directory."""
    root = Path(directory).resolve()
    if not root.exists():
        return []
    firmware_files: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() in FIRMWARE_EXTS:
            firmware_files.append(path)
    return firmware_files


def _analyze_one(
    firmware_path: str | Path,
    *,
    scope: str = "",
    max_iterations: int = 5,
    token_limit: int = 100000,
    output_root: str | Path = "output",
) -> dict[str, Any]:
    """Run vulnagent against a single firmware file and save output."""
    from vulnagent.orchestrator import VulnOrchestrator
    from vulnagent.llm import ModelRouter
    from vulnagent.utils.settings import SettingsManager
    from vulnagent.paths import PROJECT_ROOT

    fw_path = Path(firmware_path).resolve()
    fw_name = fw_path.stem
    out_dir = Path(output_root).resolve() / fw_name
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*60}")
    print(f"  {fw_path.name} ({fw_path.stat().st_size//1024}KB)")

    t0 = time.perf_counter()
    settings = SettingsManager(PROJECT_ROOT).load()
    registry = settings.create_model_registry()
    if not registry.is_ready():
        return {"error": "No LLM provider ready", "firmware": str(fw_path)}

    router = ModelRouter(registry)
    scope_text = scope or f"automated firmware triage — {fw_path.name}"
    result = VulnOrchestrator(router).run(
        target=str(fw_path),
        scope=scope_text,
        max_iterations=max_iterations,
        token_limit=token_limit,
    )
    elapsed = time.perf_counter() - t0

    report = result.get("report", "") or ""
    findings = result.get("findings", []) or []

    # Save report
    (out_dir / "report.md").write_text(report, encoding="utf-8")
    # Save findings
    (out_dir / "findings.json").write_text(
        json.dumps(findings, indent=2, ensure_ascii=False, default=str), encoding="utf-8",
    )

    tools_called = result.get("tools_called", [])
    summary = {
        "firmware": str(fw_path),
        "firmware_name": fw_name,
        "size_bytes": fw_path.stat().st_size,
        "run_id": result.get("run_id", ""),
        "success": result.get("success", False),
        "duration_seconds": round(elapsed, 1),
        "iterations": result.get("iterations", 0),
        "tokens_used": result.get("tokens_used", 0),
        "tools_called": len(tools_called),
        "findings_total": len(findings),
        "findings_critical": sum(1 for f in findings if str(f.get("severity", "")).lower() == "critical"),
        "findings_high": sum(1 for f in findings if str(f.get("severity", "")).lower() == "high"),
        "findings_medium": sum(1 for f in findings if str(f.get("severity", "")).lower() == "medium"),
        "findings_low": sum(1 for f in findings if str(f.get("severity", "")).lower() == "low"),
        "poc_count": report.count("Script:") if report else 0,
        "cwe_78": report.count("CWE-78") if report else 0,
        "cwe_798": report.count("CWE-798") if report else 0,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
    }
    (out_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8",
    )

    print(f"  Findings: {len(findings)} ({summary['findings_high']}H/{summary['findings_medium']}M)")
    print(f"  PoCs: {summary['poc_count']}  CWE-78:{summary['cwe_78']}  CWE-798:{summary['cwe_798']}")
    print(f"  {elapsed:.0f}s  {result.get('tokens_used',0)} tokens  -> {out_dir}")
    return summary


def _build_index(output_root: str | Path) -> str:
    """Build index.html summarizing all analysis results."""
    out = Path(output_root).resolve()
    summaries = []
    for sf in sorted(out.rglob("summary.json")):
        try:
            summaries.append(json.loads(sf.read_text(encoding="utf-8")))
        except Exception:
            continue
    if not summaries:
        return ""

    rows = ""
    for s in summaries:
        fname = s.get("firmware_name", "?")
        n = s.get("findings_total", 0)
        crit, high = s.get("findings_critical", 0), s.get("findings_high", 0)
        pocs = s.get("poc_count", 0)
        dur = s.get("duration_seconds", 0)
        tok = s.get("tokens_used", 0)
        c78, c798 = s.get("cwe_78", 0), s.get("cwe_798", 0)
        kb = s.get("size_bytes", 0) // 1024
        sz = f"{kb//1024}MB" if kb > 1024 else f"{kb}KB"
        color = "#f47067" if crit > 0 or high >= 2 else ("#ffb454" if high >= 1 else "#7ee787")
        rows += f"<tr><td><a href='{fname}/report.md'>{fname}</a></td><td>{sz}</td><td style='color:{color}'>{n}</td><td>{crit}+{high}</td><td>{pocs}</td><td>{c78}+{c798}</td><td>{dur:.0f}s</td><td>{tok:,}</td><td><a href='{fname}/report.md'>md</a> <a href='{fname}/findings.json'>json</a></td></tr>"

    tf = sum(s.get("findings_total", 0) for s in summaries)
    tp = sum(s.get("poc_count", 0) for s in summaries)
    tc78 = sum(s.get("cwe_78", 0) for s in summaries)
    tc798 = sum(s.get("cwe_798", 0) for s in summaries)

    html = f"""<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><title>vulnagent — 0day Results</title>
<style>
:root{{--bg:#0f1419;--panel:#151c24;--border:#2f3b49;--text:#e6edf3;--muted:#9fb0c3;--accent:#55d6be;--danger:#f47067;--warn:#ffb454;--success:#7ee787}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,sans-serif}}
.container{{max-width:1200px;margin:0 auto;padding:24px}}
h1{{font-size:28px;margin:0 0 8px}} h2{{font-size:18px;margin:24px 0 12px;color:var(--accent)}}
.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:16px 0}}
.stat{{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:16px;text-align:center}}
.stat .num{{font-size:32px;font-weight:700;display:block}} .stat .label{{font-size:12px;color:var(--muted);margin-top:4px}}
table{{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--border);border-radius:8px;overflow:hidden}}
th{{text-align:left;padding:12px 16px;background:rgba(15,20,25,0.7);font-size:12px;color:var(--muted);border-bottom:1px solid var(--border)}}
td{{padding:10px 16px;font-size:13px;border-bottom:1px solid rgba(47,59,73,0.5)}}
tr:hover{{background:rgba(85,214,190,0.05)}} a{{color:var(--accent);text-decoration:none}}
.footer{{margin-top:32px;padding-top:16px;border-top:1px solid var(--border);color:var(--muted);font-size:12px}}
</style></head><body><div class="container">
<h1>vulnagent — Firmware 0day Analysis</h1>
<p style="color:var(--muted);font-size:14px">{len(summaries)} firmware analyzed · {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</p>
<div class="stats">
<div class="stat"><span class="num">{len(summaries)}</span><span class="label">Firmware</span></div>
<div class="stat"><span class="num">{tf}</span><span class="label">Findings</span></div>
<div class="stat"><span class="num">{tp}</span><span class="label">PoC Scripts</span></div>
<div class="stat"><span class="num">{tc78}+{tc798}</span><span class="label">CWE-78 + CWE-798</span></div>
</div>
<table><thead><tr><th>Firmware</th><th>Size</th><th>Findings</th><th>Crit+High</th><th>PoCs</th><th>CWE</th><th>Time</th><th>Tokens</th><th>Links</th></tr></thead><tbody>{rows}</tbody></table>
<div class="footer">Generated by vulnagent — <a href="https://github.com">github.com</a></div>
</div></body></html>"""

    idx = out / "index.html"
    idx.write_text(html, encoding="utf-8")
    return str(idx)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="vulnagent batch 0day pipeline")
    parser.add_argument("--dir", default="firmware")
    parser.add_argument("--output", default="output")
    parser.add_argument("--single", default="")
    parser.add_argument("--max-iterations", type=int, default=5)
    parser.add_argument("--token-limit", type=int, default=100000)
    parser.add_argument("--scope", default="")
    args = parser.parse_args(argv)

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

    if args.single:
        firmware_files = [Path(args.single).resolve()]
        if not firmware_files[0].exists():
            print(f"Error: {args.single} not found", file=sys.stderr)
            return 1
    else:
        firmware_files = _find_firmware_files(args.dir)

    if not firmware_files:
        print(f"No firmware found in {args.dir}. Supported exts: {', '.join(sorted(FIRMWARE_EXTS))}")
        return 1

    print(f"Batch: {len(firmware_files)} firmware  ->  {Path(args.output).resolve()}")
    all_ok, errors = [], []

    for i, fw in enumerate(firmware_files, 1):
        print(f"\n[{i}/{len(firmware_files)}]", end="")
        try:
            s = _analyze_one(fw, scope=args.scope, max_iterations=args.max_iterations, token_limit=args.token_limit, output_root=args.output)
            (all_ok if not s.get("error") else errors).append(s)
        except KeyboardInterrupt:
            print("\nInterrupted.")
            break
        except Exception as exc:
            errors.append({"firmware": str(fw), "error": str(exc)})
            print(f"  ERROR: {exc}")

    idx = _build_index(args.output)
    if idx:
        print(f"\nIndex: file:///{idx}")
    print(f"Done: {len(all_ok)} ok, {len(errors)} errors")
    for e in errors:
        print(f"  - {e}")
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
