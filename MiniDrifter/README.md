# MiniDrifter

**MiniDrifter** is a hybrid framework for detecting **RR-Drift** (resource-reference drift) propagation threats in mini-programs.

It implements the approach in the paper:

1. **Static drift-oriented taint analysis** — RCR → RPGraph → risky RR-Drift propagation chains  
2. **Dynamic perturbation validation** with adaptive execution repair  

## Runtime Environment

The MiniDrifter framework runs on an Ubuntu 24.04 LTS server with a 24-core CPU, 64 GB of memory, and Python 3.12.5, using eight parallel worker processes.

See also [`RUNTIME_ENVIRONMENT.md`](RUNTIME_ENVIRONMENT.md).

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

Rebuild propagation artifacts on an existing pack:

```bash
python -m minidrifter.cli paper-static -i /path/to/OUTPUT
```

`--platform` selects the mini-program API surface (default `wechat`): `wechat`, `alipay`, `baidu`, `tiktok`.

## Main outputs under `OUTPUT/`

| File | Description |
|------|-------------|
| `rcr_pack.json` | Per-request reference contracts recovered from the mini program |
| `rpgraph.json` | Reference propagation graph over API / reference nodes and edges |
| `rrdrift_propagation_chains.json` | Candidate RR-Drift chains from drift sources to sensitive sinks |
| `workflows.json` | Convenience export of the same chain set |
| `drift_plans.json` | Plans used by the dynamic validator to perturb source references |

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
