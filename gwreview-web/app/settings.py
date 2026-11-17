"""Settings from environment. Nothing secret is hard-coded."""
import os
import pathlib
from cryptography.fernet import Fernet

DATA_DIR = pathlib.Path(os.environ.get("GWR_DATA_DIR", "./data")).resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "gwreview.sqlite"

def _key(name, maker):
    p = DATA_DIR / name
    env = os.environ.get("GWR_" + name.upper().replace(".", "_"))
    if env:
        return env.encode()
    if not p.exists():
        p.write_bytes(maker()); p.chmod(0o600)
    return p.read_bytes().strip()

SECRET_KEY = _key("secret.key", lambda: os.urandom(32).hex().encode())      # signs login cookies
FERNET = Fernet(_key("fernet.key", Fernet.generate_key))                      # encrypts saved browser sessions at rest

SESSION_HOURS = int(os.environ.get("GWR_SESSION_HOURS", "8"))
COOKIE_SECURE = os.environ.get("GWR_COOKIE_SECURE", "0") == "1"                # set to 1 behind TLS
ALLOW_HTTP = os.environ.get("GWR_ALLOW_HTTP", "0") == "1"                      # tests / lab only
ALLOW_PRIVATE = os.environ.get("GWR_ALLOW_PRIVATE_TARGETS", "0") == "1"        # internal targets: off by default (SSRF protection)
HEADED = os.environ.get("GWR_HEADED", "0") == "1"                              # real browser window (local installs, FIDO keys)
MAX_UPLOAD_MB = int(os.environ.get("GWR_MAX_UPLOAD_MB", "500"))
MAX_UNPACKED_MB = int(os.environ.get("GWR_MAX_UNPACKED_MB", "2000"))
MAX_FILES = int(os.environ.get("GWR_MAX_FILES", "200000"))
HARD_MIN_INTERVAL = 0.5
HARD_MAX_REQUESTS = 2000
OKTA_HOSTS = (".okta.com", ".oktapreview.com", ".okta-emea.com", ".okta-gov.com", ".trexcloud.com")

# Static assets the Okta sign-in widget and its CAPTCHA load. Allowed for sub-resources only (never as a navigation target).
IDP_ASSET_HOSTS = (".oktacdn.com", ".okta-emea.com", ".oktapreview.com", ".okta.com", "hcaptcha.com", ".hcaptcha.com", ".recaptcha.net", "www.gstatic.com") + \
    tuple(h.strip().lower() for h in os.environ.get("GWR_IDP_ASSET_HOSTS", "").split(",") if h.strip())
