# MiniDrifter

**MiniDrifter** detects **RR-Drift** (resource-reference drift) propagation threats in mini programs. It combines:

1. **Static analysis** — recover request contracts, build a reference-propagation graph, and find candidate drift chains from sources to sensitive sinks  
2. **Dynamic validation** — perturb source references and repair failed executions when needed  

## Runtime Environment

Linux (Ubuntu 24.04 LTS recommended), Python 3.12.5. The evaluation server used 24 CPU cores, 64 GB RAM, and 8 worker processes.

See [RUNTIME_ENVIRONMENT.md](RUNTIME_ENVIRONMENT.md) for details.

## Install

```bash
cd MiniDrifter
pip install -e .
```

Optional JS call-site helper:

```bash
cd tools/jsparser
npm install
```

## Analyze

```bash
python -m minidrifter.cli analyze \
  --input /path/to/unpacked-miniapp \
  --output /path/to/OUTPUT \
  --platform wechat
```

Rebuild static artifacts on an existing OUTPUT directory:

```bash
python -m minidrifter.cli paper-static -i /path/to/OUTPUT
```

Platform flag: **--platform** (default **wechat**). Allowed values: **wechat**, **alipay**, **baidu**, **tiktok**.

## Main outputs under OUTPUT/

| File | Description |
|------|-------------|
| rcr_pack.json | Per-request reference contracts recovered from the mini program |
| rpgraph.json | Reference propagation graph over API / reference nodes and edges |
| rrdrift_propagation_chains.json | Candidate RR-Drift chains from drift sources to sensitive sinks |
| workflows.json | Convenience export of the same chain set |
| drift_plans.json | Plans used by the dynamic validator to perturb source references |

## Layout

```text
MiniDrifter/
├── minidrifter/          # tool source (CLI, static analysis, runtime validation)
├── tests/
├── tools/jsparser/       # optional JS call-site scanner
├── pyproject.toml
├── RUNTIME_ENVIRONMENT.md
└── README.md
```
