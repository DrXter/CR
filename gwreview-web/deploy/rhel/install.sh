#!/usr/bin/env bash
# gwreview installer for RHEL 8 / 9 (and Rocky / Alma). Run as root from the unzipped project folder:
#   sudo bash deploy/rhel/install.sh [--no-nginx] [--port 8080] [--hostname review.example.com]
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Run as root (sudo)."; exit 1; }
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
APP=/opt/gwreview; DATA=/var/lib/gwreview; ETC=/etc/gwreview; PW=/opt/gwreview/pw
PORT=8080; NGINX=1; DATADIR=""; HOST="$(hostname -f 2>/dev/null || hostname)"
while [[ $# -gt 0 ]]; do case $1 in
  --no-nginx) NGINX=0;; --port) PORT=$2; shift;; --hostname) HOST=$2; shift;; --datadir) DATADIR=${2%/}; shift;; *) echo "Unknown option $1"; exit 1;; esac; shift; done


echo "== disk space"
dnf clean all >/dev/null 2>&1 || true; journalctl --vacuum-size=100M >/dev/null 2>&1 || true; rm -rf /root/.cache/pip
ROOT_FREE_KB=$(df -Pk / | awk 'NR==2{print $4}'); NEED_KB=3145728     # 3 GB for Chromium, libraries, virtualenv
if [[ -z $DATADIR && $ROOT_FREE_KB -lt $NEED_KB ]]; then
  # pick the real disk (xfs/ext4/btrfs) with the most free space, ignoring / /boot docker snap and tmpfs mounts
  DATADIR=$(df -Pk -T 2>/dev/null | awk 'NR>1 && ($2=="xfs"||$2=="ext4"||$2=="ext3"||$2=="btrfs") && $7!="/" && $7!~/^\/boot/ && $7!~/^\/var\/lib\/(docker|snapd)/ && $5>=5242880 {print $5, $7}' | sort -rn | head -1 | awk '{print $2}')
  [[ -n $DATADIR ]] && echo "/ has only $((ROOT_FREE_KB/1024)) MB free; using $DATADIR instead." \
    || { echo "/ has only $((ROOT_FREE_KB/1024)) MB free and no other disk with 5 GB free was found. Free space or pass --datadir /path."; exit 1; }
fi
if [[ -n $DATADIR ]]; then
  [[ -d $DATADIR ]] || { echo "$DATADIR does not exist."; exit 1; }
  echo "== relocating app and data to $DATADIR (bind mounts)"
  systemctl stop gwreview 2>/dev/null || true
  shopt -s dotglob nullglob
  for pair in "$APP:$DATADIR/gwreview" "$DATA:$DATADIR/gwreview-data"; do
    tgt=${pair%%:*}; src=${pair#*:}; mkdir -p "$src" "$tgt"
    if ! mountpoint -q "$tgt"; then
      files=("$tgt"/*); [[ ${#files[@]} -gt 0 ]] && mv "${files[@]}" "$src"/    # keep anything an earlier run left on /
      mount --bind "$src" "$tgt"
    fi
    grep -qs " $tgt " /etc/fstab || echo "$src $tgt none bind 0 0" >> /etc/fstab
  done
  shopt -u dotglob nullglob; systemctl daemon-reload
  df -h "$APP" | tail -1
fi
[[ $(df -Pk / | awk 'NR==2{print $4}') -ge 102400 || -n $DATADIR ]] || { echo "Less than 100 MB free on /. Free space first."; exit 1; }

. /etc/os-release
echo "== RHEL family $VERSION_ID"
[[ ${VERSION_ID%%.*} -ge 8 ]] || { echo "RHEL 8 or newer is required (Chromium needs a recent glibc)."; exit 1; }

echo "== Python 3.11"
PY=""
for c in python3.12 python3.11 python3.10 python3.9; do command -v $c >/dev/null && { PY=$c; break; }; done
if [[ -z $PY ]]; then dnf install -y python3.11 python3.11-pip python3.11-devel || dnf install -y python3.12 python3.12-pip python3.12-devel; PY=$(command -v python3.11 || command -v python3.12); fi
echo "using $($PY --version)"

echo "== Chromium system libraries"
dnf install -y --setopt=strict=0 libatomic nss nspr atk at-spi2-atk at-spi2-core cups-libs libdrm libxkbcommon libXcomposite libXdamage libXfixes libXrandr libXext libX11 libxcb \
  mesa-libgbm alsa-lib pango cairo glib2 dbus-libs expat fontconfig freetype liberation-fonts policycoreutils-python-utils curl tar unzip

echo "== user, folders"
id gwreview >/dev/null 2>&1 || useradd --system --home-dir $APP --shell /sbin/nologin gwreview
mkdir -p $APP $DATA $ETC; cp -r "$SRC/app" "$SRC/requirements.txt" $APP/
chown -R gwreview:gwreview $APP $DATA; chmod 700 $DATA

echo "== virtualenv and packages"
$PY -m venv $APP/venv
$APP/venv/bin/python -m pip install --upgrade pip setuptools wheel
$APP/venv/bin/python -m pip install -r $APP/requirements.txt
mkdir -p $PW; PLAYWRIGHT_BROWSERS_PATH=$PW $APP/venv/bin/python -m playwright install chromium; chown -R gwreview:gwreview $APP

echo "== configuration"
if [[ ! -f $ETC/gwreview.env ]]; then
  ADMINPW=$(head -c 24 /dev/urandom | base64 | tr -d '=+/' | cut -c1-20)
  cat > $ETC/gwreview.env <<EOT
GWR_DATA_DIR=$DATA
GWR_HOST=127.0.0.1
GWR_PORT=$PORT
GWR_ADMIN_PASSWORD=${ADMINPW}Aa1
GWR_COOKIE_SECURE=$([[ $NGINX -eq 1 ]] && echo 1 || echo 0)
PLAYWRIGHT_BROWSERS_PATH=$PW
EOT
  chmod 600 $ETC/gwreview.env; chown root:gwreview $ETC/gwreview.env; chmod 640 $ETC/gwreview.env
  echo "Admin password written to $ETC/gwreview.env (user: admin). Change it after the first sign-in."
fi

echo "== systemd"
install -m 644 "$SRC/deploy/rhel/gwreview.service" /etc/systemd/system/gwreview.service
systemctl daemon-reload; systemctl enable --now gwreview

echo "== SELinux labels"
if [[ -n $DATADIR ]]; then semanage fcontext -a -e /opt/gwreview "$DATADIR/gwreview" 2>/dev/null || true; semanage fcontext -a -e /var/lib/gwreview "$DATADIR/gwreview-data" 2>/dev/null || true; restorecon -R "$DATADIR/gwreview" "$DATADIR/gwreview-data" 2>/dev/null || true; fi
restorecon -R $APP $DATA 2>/dev/null || true

if [[ $NGINX -eq 1 ]]; then
  echo "== nginx with TLS"
  dnf install -y nginx openssl
  mkdir -p /etc/pki/gwreview
  if [[ ! -f /etc/pki/gwreview/tls.crt ]]; then
    openssl req -x509 -nodes -newkey rsa:3072 -days 365 -subj "/CN=$HOST" -addext "subjectAltName=DNS:$HOST" \
      -keyout /etc/pki/gwreview/tls.key -out /etc/pki/gwreview/tls.crt
    chmod 600 /etc/pki/gwreview/tls.key
    echo "Self-signed certificate created. Replace /etc/pki/gwreview/tls.crt and tls.key with your CA-issued pair when you have one."
  fi
  sed -e "s/__HOST__/$HOST/" -e "s/__PORT__/$PORT/" "$SRC/deploy/rhel/nginx-gwreview.conf" > /etc/nginx/conf.d/gwreview.conf
  setsebool -P httpd_can_network_connect 1
  nginx -t && systemctl enable --now nginx && systemctl reload nginx
  if systemctl is-active --quiet firewalld; then firewall-cmd --permanent --add-service=https && firewall-cmd --reload; fi
  URL="https://$HOST/"
else
  URL="http://127.0.0.1:$PORT/ (loopback only; use an SSH tunnel: ssh -L $PORT:127.0.0.1:$PORT user@$HOST)"
fi

echo "== check"
sleep 3; curl -fsS "http://127.0.0.1:$PORT/api/health" && echo
sudo -u gwreview env PLAYWRIGHT_BROWSERS_PATH=$PW $APP/venv/bin/python -c "
from playwright.sync_api import sync_playwright as p
with p() as x:
    b=x.chromium.launch(); print('Chromium OK', b.version); b.close()" || echo "Chromium failed to start: run ldd on the browser binary under $PW and install the missing libraries."
echo; echo "Done. Open $URL and sign in as admin. Password: grep GWR_ADMIN_PASSWORD $ETC/gwreview.env"
echo "Logs: journalctl -u gwreview -f"
