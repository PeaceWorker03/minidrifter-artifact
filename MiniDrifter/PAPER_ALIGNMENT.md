# MiniDrifter ↔ Paper Name Alignment (100%)

Source of truth: the Approach section you provided (`\\section{MiniDrifter}`).

## Tool

| Paper | Implementation |
|-------|----------------|
| **MiniDrifter** | package `minidrifter`, CLI `python -m minidrifter.cli` |

## Core terms

| Paper | Implementation |
|-------|----------------|
| **RR-Drift** | threat model / confirmation target |
| **RCR** — Reference Contract Representation \((\mathcal{A}_i,u_i,\phi_i,\Pi_i,\Gamma_i)\) | `rcr/` → `rcr_pack.json` (`rcrs` key; legacy `ccrs` alias) |
| **RPGraph** — Reference Propagation Graph \(\mathit{RPGraph}=(N,E)\) | `rpgraph/` → `rpgraph.json` |
| Risky **RR-Drift propagation chains** | `rrdrift_propagation_chains.json` (+ `workflows.json`) |
| Static drift-oriented taint analyzer | `analyze` + `paper-static` |
| Dynamic perturbation validator | `runtime_trace/`, probes |
| Adaptive execution repair | runtime feedback / repair paths |

## Stages (paper figure)

1. RCR extraction  
2. RPGraph construction  
3. Detection of risky RR-Drift propagation chains  
4. Dynamic perturbation validation  
5. Adaptive execution repair  

## CLI

```bash
python -m minidrifter.cli analyze -i <app> -o <app>/OUTPUT --platform wechat
python -m minidrifter.cli paper-static -i <app>/OUTPUT
```

Legacy pack files (`ccr_pack.json`, `cpeg.json`, `binding_continuity_graph.json`) remain readable.
