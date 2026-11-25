import getpass
import os
import sys

import uvicorn


def reset_admin():
    """python -m app reset-admin  -> sets a new password for 'admin' (creates it if missing) and re-enables it."""
    from . import db, security
    pw = os.environ.get("GWR_ADMIN_PASSWORD") or getpass.getpass("New admin password (12+ characters): ")
    if len(pw) < 12:
        sys.exit("Password must be at least 12 characters.")
    if db.q("SELECT 1 FROM users WHERE username='admin'", one=True):
        db.x("UPDATE users SET pw_hash=?, role='admin', active=1 WHERE username='admin'", (security.hash_pw(pw),))
    else:
        db.x("INSERT INTO users(username,pw_hash,role,created) VALUES(?,?,?,strftime('%s','now'))", ("admin", security.hash_pw(pw), "admin"))
    db.audit("system", "admin_password_reset")
    print("Admin password updated. Start the server and sign in as 'admin'.")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "reset-admin":
        reset_admin()
    else:
        uvicorn.run("app.main:app", host=os.environ.get("GWR_HOST", "127.0.0.1"), port=int(os.environ.get("GWR_PORT", "8080")), log_level="info")
