#!/usr/bin/env python3
"""Resumen diario de Cowrie enviado a Telegram.
Lee TG_TOKEN y TG_CHAT_ID de /root/.telegram.env (fuera del repo)."""
import os, json, gzip, glob, uuid, urllib.request
from collections import Counter
from datetime import datetime, timedelta, timezone

LOG_DIR = "/var/lib/docker/volumes/cowrie-var/_data/log/cowrie"
OUT_DIR = "/root/honeypot-logs"

env = {}
for l in open("/root/.telegram.env"):
    if "=" in l:
        k, v = l.strip().split("=", 1)
        env[k] = v
TOKEN, CHAT = env["TG_TOKEN"], env["TG_CHAT_ID"]

now = datetime.now(timezone.utc)
since = now - timedelta(days=1)
events = []
for f in glob.glob(LOG_DIR + "/cowrie.json*"):
    if os.path.getmtime(f) < since.timestamp():
        continue
    for line in open(f, errors="replace"):
        try:
            e = json.loads(line)
            ts = datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00"))
        except (ValueError, KeyError):
            continue
        if ts >= since:
            events.append(e)

os.makedirs(OUT_DIR, exist_ok=True)
name = f"{OUT_DIR}/cowrie-{now:%Y-%m-%d}.json.gz"
with gzip.open(name, "wt") as g:
    for e in events:
        g.write(json.dumps(e) + "\n")

ev = lambda i: [e for e in events if e.get("eventid") == i]
conns = ev("cowrie.session.connect")
oks = ev("cowrie.login.success")
logins = ev("cowrie.login.failed") + oks
cmds = ev("cowrie.command.input")
top = lambda items, n=5: "\n".join(
    f"  {k} ({v})" for k, v in Counter(items).most_common(n)) or "  -"

text = (
    f"Honeypot {now:%Y-%m-%d}\n"
    f"Conexiones: {len(conns)} | IPs únicas: {len({e['src_ip'] for e in conns})}\n"
    f"Logins: {len(logins)} (exitosos: {len(oks)}) | Comandos: {len(cmds)}\n"
    f"Top IPs:\n{top(e['src_ip'] for e in conns)}\n"
    f"Top usuarios:\n{top(e.get('username') for e in logins)}\n"
    f"Top contraseñas:\n{top(e.get('password') for e in logins)}"
)

def tg(method, fields, path=None):
    b = uuid.uuid4().hex
    body = b""
    for k, v in fields.items():
        body += (f'--{b}\r\nContent-Disposition: form-data; name="{k}"'
                 f'\r\n\r\n{v}\r\n').encode()
    if path:
        body += (f'--{b}\r\nContent-Disposition: form-data; name="document"; '
                 f'filename="{os.path.basename(path)}"\r\n'
                 f'Content-Type: application/gzip\r\n\r\n').encode()
        body += open(path, "rb").read() + b"\r\n"
    body += f"--{b}--\r\n".encode()
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{TOKEN}/{method}", body,
        {"Content-Type": f"multipart/form-data; boundary={b}"})
    return urllib.request.urlopen(req, timeout=60).read()

tg("sendMessage", {"chat_id": CHAT, "text": text})
if os.path.getsize(name) < 49 * 1024 * 1024:
    tg("sendDocument", {"chat_id": CHAT}, name)
else:
    tg("sendMessage", {"chat_id": CHAT, "text": "Archivo >50 MB, queda en el servidor"})
