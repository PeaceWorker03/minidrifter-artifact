# MiniDrifter

**MiniDrifter** is a hybrid framework for detecting **RR-Drift** (resource-reference drift) propagation threats in mini-programs.

It implements the approach in the paper:

1. **Static drift-oriented taint analysis** — RCR → RPGraph → risky RR-Drift propagation chains  
2. **Dynamic perturbation validation** with adaptive execution repair  

Paper name alignment (tool / artifacts / stages) is documented in [`PAPER_ALIGNMENT.md`](PAPER_ALIGNMENT.md).

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

## Analyze (paper static pipeline)

```bash
python -m minidrifter.cli analyze \
  --input /path/to/unpacked-miniapp \
  --output /path/to/OUTPUT \
  --platform wechat
```

Rebuild RCR / RPGraph / RR-Drift chains on an existing pack:

```bash
python -m minidrifter.cli paper-static -i /path/to/OUTPUT
```

Supported `--platform` values include `wechat`, `qq`, `alipay`, `douyin`, `baidu`.

## Paper artifacts under `OUTPUT/`

| Artifact | Paper term |
|----------|------------|
| `rcr_pack.json` | **RCR** — Reference Contract Representation |
| `rpgraph.json` | **RPGraph** — Reference Propagation Graph \((N,E)\) |
| `rrdrift_propagation_chains.json` | Risky **RR-Drift propagation chains** |
| `workflows.json` | Alias of chain set |
| `drift_plans.json` | Perturbation plans for dynamic validation |

## Layout

```text
MiniDrifter/
├── minidrifter/          # tool source (CLI, RCR, RPGraph, RR-Drift, runtime)
├── tests/                # unit / regression tests
├── tools/jsparser/       # optional JS call-site scanner
├── pyproject.toml
├── PAPER_ALIGNMENT.md
├── RUNTIME_ENVIRONMENT.md
└── README.md
```
