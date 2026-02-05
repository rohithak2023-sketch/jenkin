# sender_web.py
# Run:  python sender_web.py
# UI:   http://localhost:5000
# Auto-discovery finds the receiver on your LAN (UDP 9998),
# then sends hybrid-encrypted messages to receiver's TCP:9999

import base64
import hashlib
import os
import socket
import struct
import threading
import time
from datetime import datetime
from typing import List, Dict, Optional

from flask import Flask, request, jsonify, render_template_string
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ------------------ Config ------------------
HTTP_PORT = 5000
TCP_PORT = 9999
UDP_DISCOVERY_PORT = 9998
UDP_DISCOVERY_TOKEN = b"DISCOVER_SECURE_RECEIVER_V1"
DISCOVERY_TIMEOUT = 1.5   # seconds per try
DISCOVERY_TRIES = 3
SEND_TRIES = 3
TCP_TIMEOUT = 4.0
APP_TITLE = "Sender — Hybrid Crypto (LAN Demo)"

# ------------------ State -------------------
app = Flask(__name__)
_history: List[Dict] = []
_receiver_ip: Optional[str] = None

# ------------------ Helpers -----------------
def b64(x: bytes) -> str:
    return base64.b64encode(x).decode("utf-8")

def discover_receiver() -> Optional[str]:
    """Broadcast a discovery packet and wait for a reply."""
    print("[DISCOVER] Trying to find receiver...")
    ip = None
    for attempt in range(1, DISCOVERY_TRIES + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.settimeout(DISCOVERY_TIMEOUT)
            s.sendto(UDP_DISCOVERY_TOKEN, ("255.255.255.255", UDP_DISCOVERY_PORT))
            data, addr = s.recvfrom(4096)
            if data.startswith(b"RECEIVER_HERE:"):
                ip = addr[0]
                print(f"[DISCOVER] Receiver at {ip}")
                return ip
        except socket.timeout:
            print(f"[DISCOVER] Timeout {attempt}/{DISCOVERY_TRIES}")
        except Exception as e:
            print("[DISCOVER] Error:", e)
        finally:
            try:
                s.close()
            except:
                pass
    return ip

def recv_all(sock, n):
    data = b""
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            raise ConnectionError("Socket closed early")
        data += packet
    return data

def send_message(receiver_ip: str, plain_text: str) -> Dict:
    """Hybrid encrypt + send. Returns a details dict for UI/history."""
    # Connect with retries
    last_error = None
    for attempt in range(1, SEND_TRIES + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(TCP_TIMEOUT)
            s.connect((receiver_ip, TCP_PORT))

            # Receive public key (length-prefixed)
            raw = recv_all(s, 4)
            pub_len = struct.unpack("!I", raw)[0]
            public_pem = recv_all(s, pub_len)
            public_key = serialization.load_pem_public_key(public_pem)

            # Generate AES-256 key + IV
            aes_key = os.urandom(32)
            iv = os.urandom(16)

            # Encrypt message
            plaintext_bytes = plain_text.encode("utf-8")
            encryptor = Cipher(algorithms.AES(aes_key), modes.CFB(iv)).encryptor()
            ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()

            # Encrypt AES key with RSA-OAEP
            enc_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            # Integrity hash (SHA-256 of ciphertext)
            msg_hash = hashlib.sha256(ciphertext).digest()

            # Send fields (length-prefixed)
            def send_field(data: bytes):
                s.sendall(struct.pack("!I", len(data)))
                s.sendall(data)

            send_field(enc_key)
            send_field(iv)
            send_field(ciphertext)
            send_field(msg_hash)

            # Build detail dict
            details = {
                "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "to": f"{receiver_ip}:{TCP_PORT}",
                "plaintext": plain_text,
                "aes_key_b64": b64(aes_key),
                "iv_b64": b64(iv),
                "ciphertext_b64": b64(ciphertext),
                "sha256_b64": b64(msg_hash),
                "status": "Sent ✓",
                "attempt": attempt
            }
            s.close()
            return details
        except Exception as e:
            last_error = str(e)
            print(f"[SEND] Attempt {attempt}/{SEND_TRIES} failed:", e)
            time.sleep(0.6)

    # Failed after retries
    return {
        "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "to": f"{receiver_ip}:{TCP_PORT}",
        "plaintext": plain_text,
        "aes_key_b64": "",
        "iv_b64": "",
        "ciphertext_b64": "",
        "sha256_b64": "",
        "status": f"Failed after retries: {last_error}",
        "attempt": SEND_TRIES
    }

# ------------------ Flask UI ----------------
DASH = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>{{ title }}</title>
<style>
:root{
  --bg:#0a0f1e; --panel:#10172a; --muted:#a8b3c7; --text:#e7eef7;
  --acc1:#00d4ff; --acc2:#7c4dff; --ok:#16a34a; --bad:#ef4444; --border:#1f2a44;
}
*{box-sizing:border-box} body{margin:0;background:linear-gradient(180deg,#090d1a,#0c1224);color:var(--text);
  font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial}
.container{max-width:1050px;margin:28px auto;padding:0 16px}
.card{background:linear-gradient(180deg,rgba(255,255,255,0.03),rgba(255,255,255,0.02));
  border:1px solid var(--border); border-radius:16px; padding:18px}
.h{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px}
.logo{display:flex;align-items:center;gap:12px}
.logo .badge{font-size:12px;border:1px solid var(--border);padding:4px 8px;border-radius:999px;color:var(--muted)}
h1{margin:0;font-size:22px}
.btn{padding:10px 14px;border-radius:12px;border:1px solid var(--border);background:#0e1530;color:var(--text);cursor:pointer}
.btn-primary{background:linear-gradient(90deg,var(--acc1),var(--acc2));border:0;color:#fff}
.input{width:100%;padding:12px;border-radius:12px;border:1px solid var(--border);background:rgba(255,255,255,0.02);color:var(--text)}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media (max-width:950px){.grid{grid-template-columns:1fr}}
.item{border:1px solid var(--border);border-radius:14px;padding:12px;background:rgba(255,255,255,0.02)}
.kv{display:grid;grid-template-columns:160px 1fr;gap:10px;margin:6px 0;color:var(--muted)}
.tag{font-size:12px;color:#fff;background:rgba(255,255,255,0.08);border:1px solid var(--border);padding:3px 8px;border-radius:999px;margin-left:8px}
.small{font-size:12px;color:var(--muted)}
hr{border:0;border-top:1px solid var(--border);margin:12px 0}
</style>
</head>
<body>
<div class="container">
  <div class="card">
    <div class="h">
      <div class="logo">
        <div style="font-size:28px">📤</div>
        <div>
          <h1>Sender Dashboard</h1>
          <div class="small">Enter a message, auto-discover receiver, and send securely.</div>
        </div>
      </div>
      <div>
        <span class="badge" id="statusBadge">Receiver: Unknown</span>
      </div>
    </div>

    <div class="grid">
      <div class="item">
        <div class="small">Step 1</div>
        <div style="display:flex;gap:8px;align-items:center;margin:6px 0 10px">
          <button class="btn" onclick="discover()">🔎 Auto-discover receiver</button>
          <span class="small">or</span>
          <input id="ip" class="input" placeholder="Receiver IP (optional, auto-fill after discovery)">
        </div>

        <div class="small">Step 2</div>
        <textarea id="msg" class="input" rows="4" placeholder="Type message to send..."></textarea>

        <div style="display:flex;gap:8px;margin-top:10px">
          <button class="btn btn-primary" onclick="sendMsg()">🔒 Encrypt & Send</button>
          <button class="btn" onclick="clearMsg()">Clear</button>
        </div>
      </div>

      <div class="item">
        <div style="display:flex;align-items:center;justify-content:space-between">
          <div><strong>Last Send — Details</strong></div>
          <button class="btn" onclick="refreshNow()">Refresh</button>
        </div>
        <div id="last"></div>
      </div>
    </div>

    <div class="item" style="margin-top:14px">
      <div style="display:flex;align-items:center;justify-content:space-between">
        <div><strong>Message History</strong> <span class="tag" id="countTag">0</span></div>
        <div class="small">Auto refresh every 2s</div>
      </div>
      <div id="list"></div>
    </div>
  </div>
</div>

<script>
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
function el(html){const d=document.createElement('div'); d.innerHTML=html; return d.firstElementChild;}

async function discover(){
  const r = await fetch('/api/discover', {method:'POST'});
  const js = await r.json();
  const ip = js.ip || 'Not found';
  document.getElementById('ip').value = js.ip || '';
  document.getElementById('statusBadge').textContent = 'Receiver: ' + ip;
}

async function sendMsg(){
  const ip = document.getElementById('ip').value.trim();
  const msg = document.getElementById('msg').value.trim();
  if (!ip){ alert('Set receiver IP (use Auto-discover).'); return; }
  if (!msg){ alert('Type a message.'); return; }
  const r = await fetch('/api/send', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ip, msg})
  });
  const js = await r.json();
  renderLast(js);
  load();
}

function clearMsg(){ document.getElementById('msg').value=''; }

function renderLast(row){
  const last = document.getElementById('last');
  if (!row || !row.ts){ last.innerHTML = '<div class="small">No data.</div>'; return; }
  last.innerHTML = `
    <div class="kv"><div>Status</div><div>${esc(row.status)} (attempt ${row.attempt})</div></div>
    <div class="kv"><div>Sent To</div><div>${esc(row.to)}</div></div>
    <div class="kv"><div>Plaintext</div><div>${esc(row.plaintext)}</div></div>
    <div class="kv"><div>AES Key</div><div><code>${esc(row.aes_key_b64)}</code></div></div>
    <div class="kv"><div>IV</div><div><code>${esc(row.iv_b64)}</code></div></div>
    <div class="kv"><div>Ciphertext</div><div><code>${esc(row.ciphertext_b64)}</code></div></div>
    <div class="kv"><div>SHA-256</div><div><code>${esc(row.sha256_b64)}</code></div></div>
    <div class="small">Timestamp: ${esc(row.ts)}</div>
  `;
}

async function load(){
  const r = await fetch('/api/history');
  const js = await r.json();
  document.getElementById('countTag').textContent = js.length;
  const list = document.getElementById('list');
  list.innerHTML = '';
  js.forEach(row => {
    const item = el(`
      <div class="item" style="margin-top:10px">
        <div style="display:flex;justify-content:space-between;align-items:center">
          <div><strong>${esc(row.ts)}</strong> → ${esc(row.to)}</div>
          <div>${esc(row.status)}</div>
        </div>
        <div class="kv"><div>Plaintext</div><div>${esc(row.plaintext)}</div></div>
        <div class="kv"><div>AES Key</div><div><code>${esc(row.aes_key_b64)}</code></div></div>
        <div class="kv"><div>IV</div><div><code>${esc(row.iv_b64)}</code></div></div>
        <div class="kv"><div>Ciphertext</div><div><code>${esc(row.ciphertext_b64)}</code></div></div>
        <div class="kv"><div>SHA-256</div><div><code>${esc(row.sha256_b64)}</code></div></div>
      </div>
    `);
    list.appendChild(item);
  });

  // update last panel
  if (js.length) renderLast(js[0]);
}
function refreshNow(){ load(); }
setInterval(load, 2000); load();
</script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(DASH, title=APP_TITLE)

@app.route("/api/history")
def api_history():
    return jsonify(_history)

@app.route("/api/discover", methods=["POST"])
def api_discover():
    global _receiver_ip
    ip = discover_receiver()
    _receiver_ip = ip
    return jsonify({"ip": ip})

@app.route("/api/send", methods=["POST"])
def api_send():
    global _receiver_ip
    data = request.get_json(force=True)
    ip = (data.get("ip") or _receiver_ip or "").strip()
    msg = (data.get("msg") or "").strip()
    if not ip or not msg:
        return jsonify({"error": "ip and msg required"}), 400

    details = send_message(ip, msg)
    _history.insert(0, details)
    return jsonify(details)

if __name__ == "__main__":
    print(f"[HTTP] Sender UI at http://localhost:{HTTP_PORT}")
    app.run(host="0.0.0.0", port=HTTP_PORT, debug=False, threaded=True)
