# Runtime Environment

The MiniDrifter framework runs on an Ubuntu 24.04 LTS server with a 24-core CPU, 64 GB of memory, and Python 3.12.5, using eight parallel worker processes.

## Version checklist

| Item | Version / Spec |
|------|----------------|
| OS | Ubuntu 24.04 LTS |
| CPU | 24-core |
| Memory | 64 GB |
| Python | 3.12.5 |
| Parallel workers | 8 |

## Recommended setup (Linux)

```bash
# Ubuntu 24.04 LTS
sudo apt update
sudo apt install -y python3.12 python3.12-venv python3-pip build-essential

python3.12 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .

# optional JS call-site helper
cd tools/jsparser && npm install && cd ../..
```
