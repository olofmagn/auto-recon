# Pentesting Tool For Reconnaissance
Another recon tool to quickly perform reconnaissance on a target in an organized fashion.

## 🔍 What It Does
- Automated installation process.
- Pentest scope/name labeling.
- Organised and colorized output for data processing and further explotation.

## ✅ Requirements
- Go version > 1.23
- Tools available in `installation.sh`.
- Dependencies as listed in `requirements.txt`.

## 🛠️ Installation
- Use `install.sh` to update/upgrade current system, install necessary packages and go-installations.
- Use `pip3 -r requirements.txt` if you want to install the packages independently and not via the shellscript.
- Place your API keys in textformat in `~/Projects/auto-recon/api_keys/` for correct initialization.

## 📦 Usage
Navigate to `recon/` and issue:

```bash
./recon-scan 1 target.com api
```

- `1` - PentesterID (used to identify who is running the scan or in which context)
- `target.com` - the target domain for reconnaissance
- `api` - the scope or area of the domain to focus on (e.g., "api", "web", "admin")

Example output of the initialization process:
```bash
Pentest ID: 1
Target: target.com
Scope: api
Current Path: /home/olofmagn/Projects/auto-recon
Scope Path: /scope/test
Timestamp: 11:22:26
Scan Path: /home/olofmagn/auto-recon/recon/target.com-2025-06-07
Issuer: olofmagn

```

Example output from a full script run:
```bash
ls -l /home/olofmagn/auto-recon/recon/target.com-2025-06-07/
-total 60
-drwxrwxr-x   2 olofmagn olofmagn  4096 Jun  7 21:41 ASN
-drwxrwxr-x   2 olofmagn olofmagn  4096 Jun  7 21:41 domains
-drwxrwxr-x   2 olofmagn olofmagn  4096 Jun  7 21:41 domain-takeover
-drwxrwxr-x   2 olofmagn olofmagn  4096 Jun  7 21:41 httpx
-drwxrwxr-x   2 olofmagn olofmagn  4096 Jun  7 21:41 nmap
-drwxrwxr-x 637 olofmagn olofmagn 36864 Jun  7 20:44 screenshot
```

These folders can be navigated to investigate files for further testing with other frameworks/tools.

## License
This project is open-source and licensed under the MIT License. See the LICENSE file for details.
