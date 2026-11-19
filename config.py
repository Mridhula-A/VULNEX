from pathlib import Path
import json

APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "data"
EXPORT_DIR = APP_DIR / "exports"
DB_PATH = DATA_DIR / "scanner.db"
CONFIG_PATH = APP_DIR / "config.json"

DEFAULT_PORTS = "21,22,23,25,53,80,110,135,139,143,443,445,3306,3389,5432,5900,8080,8443"
CONNECT_TIMEOUT = 0.6
MAX_WORKERS = 80
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def load_config():
    if CONFIG_PATH.exists():
        try:
            return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return {"nvd_api_key": "", "use_nmap": True, "use_scapy": False}

def save_config(data):
    CONFIG_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")

DATA_DIR.mkdir(exist_ok=True)
EXPORT_DIR.mkdir(exist_ok=True)
