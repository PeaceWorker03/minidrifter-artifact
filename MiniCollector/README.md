# MiniCollector

**MiniCollector** collects WeChat mini programs and recovers their packages for analysis.

It searches for and loads apps through **UI control localization** on Windows WeChat, captures local code packages, uses **WeDecode** for unpacking / source recovery, and classifies recovered apps into service categories.

This directory sits alongside `MiniDrifter/` and `Data/` in the artifact repository.

## Runtime Environment

The collection and package-reversing framework runs on a Windows 11 host equipped with an Intel Core i9-14900KF CPU (24 cores / 32 threads) and 32 GB of memory (WeChat 4.x desktop client).

## Components

| Script | Role |
|--------|------|
| `open_miniprograms_ui.py` | UI-control localization: search panel → click results → load apps |
| `launch_miniprograms.py` | Optional URL-Scheme launcher to refresh local caches |
| `pipeline.py` | Batch pipeline: discover packages → WeDecode unpack → identify → classify → archive |
| `discover.py` | Locate WeChat `packages` cache roots |
| `identify.py` / `classify.py` | Naming + category assignment |
| `extract_apis.py` | API surface extraction helpers |
| `config.example.json` | Example paths / workers / WeDecode command |

## Install

```bash
cd MiniCollector
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

# WeDecode (Node)
npm install -g wedecode
```

Copy `config.example.json` to `config.json` and edit `data_root` / `wedecode_cmd` for your machine.

## Typical usage

```bash
# 1) UI collection (PC WeChat must be logged in)
python open_miniprograms_ui.py

# 2) Unpack + classify archived packages
python pipeline.py --workers 8
```

## Notes

- Requires a logged-in **WeChat Windows** client for UI collection.
- Do not commit machine-local `config.json`, progress logs, or raw package dumps.
- Collected corpus artifacts used in experiments live under `../Data/` (see repository `Data/README.md`).
