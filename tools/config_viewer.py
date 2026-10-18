#!/usr/bin/env python3
"""
MCP Auth Gateway — Config & Log Viewer
Single-file local web app. No dependencies (stdlib only).

Run:    python tools/config_viewer.py
Opens:  http://127.0.0.1:8787

Serves live contents of the project's config and log files with tabs.
Secret-looking values in .env files are masked server-side.
"""

import json
import re
import threading
import webbrowser
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

BASE = Path(__file__).resolve().parents[1]  # repo root
HOST, PORT = "127.0.0.1", 8787

# id, label, path relative to the repo root, group, mask secrets?, is log?
# fmt: off
FILES = [
    ("env",           ".env",                       ".env",                                        "Environment", True,  False),
    ("env-gen",       ".env.generated",             ".env.generated",                              "Environment", True,  False),
    ("env-ex",        ".env.example",               ".env.example",                                "Environment", False, False),
    ("compose",       "docker-compose.yml",         "docker-compose.yml",                          "Compose",     False, False),
    ("compose-agg",   "aggregate",                  "deploy/compose/docker-compose.aggregate.yml", "Compose",     False, False),
    ("compose-edge",  "edge",                       "deploy/compose/docker-compose.edge.yml",      "Compose",     False, False),
    ("compose-gh",    "github",                     "deploy/compose/docker-compose.github.yml",    "Compose",     False, False),
    ("compose-quick", "quickstart",                 "docker-compose.quickstart.yml",               "Compose",     False, False),
    ("policy",        "policy.generated",           "policy.generated.yaml",                       "Policy",      False, False),
    ("policy-agg",    "policy.aggregate.generated", "policy.aggregate.generated.yaml",             "Policy",      False, False),
    ("policy-gh",     "policy.github.generated",    "policy.github.generated.yaml",                "Policy",      False, False),
    ("policy-ex",     "policy.example",             "examples/policy.example.yaml",                "Policy",      False, False),
    ("policy-agg-ex", "policy.aggregate.example",   "examples/policy.aggregate.example.yaml",      "Policy",      False, False),
    ("policy-gh-ex",  "policy.github.example",      "examples/policy.github.example.yaml",         "Policy",      False, False),
    ("upstreams-ex",  "upstreams.example",          "examples/upstreams.example.yaml",             "Upstreams",   False, False),
    ("nginx",         "nginx.conf",                 "infra/edge/nginx.conf",                       "Infra",       False, False),
    ("entra",         "entra-output.json",          "infra/entra-output.json",                     "Infra",       False, False),
    ("manifest",      "manifest-baseline.json",     "manifest-baseline.json",                      "Infra",       False, False),
    ("dockerfile",    "Dockerfile",                 "Dockerfile",                                  "Project",     False, False),
    ("pyproject",     "pyproject.toml",             "pyproject.toml",                              "Project",     False, False),
    ("ci",            "ci.yml",                     ".github/workflows/ci.yml",                    "Project",     False, False),
    ("audit",         "audit.log",                  "audit.log",                                   "Logs",        False, True),
]
# fmt: on

SECRET_KEY_RE = re.compile(r"(secret|token|key|pass|pwd|credential|auth)", re.I)
ENV_LINE_RE = re.compile(r"^(\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*)(.+)$")


def mask_env(text: str) -> str:
    out = []
    for line in text.splitlines():
        m = ENV_LINE_RE.match(line)
        if m and SECRET_KEY_RE.search(m.group(1)) and m.group(2).strip():
            val = m.group(2).strip()
            hint = val[:3] if len(val) > 8 else ""
            out.append(f"{m.group(1)}{hint}••••••••  # masked")
        else:
            out.append(line)
    return "\n".join(out)


def read_file(entry, tail=None):
    _id, _label, rel, _group, mask, is_log = entry
    p = BASE / rel
    if not p.exists():
        return {"error": f"File not found: {rel}"}
    stat = p.stat()
    text = p.read_text(encoding="utf-8", errors="replace")
    total_lines = text.count("\n") + 1 if text else 0
    truncated = False
    if is_log and tail and total_lines > tail:
        text = "\n".join(text.splitlines()[-tail:])
        truncated = True
    if mask:
        text = mask_env(text)
    return {
        "content": text,
        "size": stat.st_size,
        "mtime": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
        "lines": total_lines,
        "truncated": truncated,
        "masked": mask,
        "path": rel,
    }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence request logging
        pass

    def _send(self, code, body, ctype):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/":
            self._send(200, PAGE, "text/html; charset=utf-8")
            return
        if url.path == "/api/manifest":
            manifest = [
                {
                    "id": f[0],
                    "label": f[1],
                    "path": f[2],
                    "group": f[3],
                    "masked": f[4],
                    "isLog": f[5],
                    "exists": (BASE / f[2]).exists(),
                }
                for f in FILES
            ]
            self._send(200, json.dumps(manifest), "application/json")
            return
        m = re.match(r"^/api/file/([\w-]+)$", url.path)
        if m:
            entry = next((f for f in FILES if f[0] == m.group(1)), None)
            if not entry:
                self._send(404, json.dumps({"error": "unknown file id"}), "application/json")
                return
            q = parse_qs(url.query)
            tail = int(q["tail"][0]) if "tail" in q else None
            self._send(200, json.dumps(read_file(entry, tail)), "application/json")
            return
        self._send(404, "not found", "text/plain")


PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>MCP Auth Gateway — Config &amp; Logs</title>
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:ital,wght@0,400;0,500;0,700;1,400;1,500&family=DM+Sans:wght@300;400;500&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet"/>
<style>
:root {
  --oled-bg:#000000; --oled-surface:#0a0a0a; --oled-surface-2:#111111; --oled-surface-3:#1a1a1a;
  --oled-border:#1a1a1a; --oled-border-mid:#2a2a2a; --oled-border-gold:#c9a96e;
  --oled-gold:#c9a96e; --oled-gold-light:#dfc08a; --oled-gold-dim:#8a6e47; --oled-gold-muted:#4a3a25;
  --oled-text:#e8e8e8; --oled-text-muted:#555555; --oled-text-subtle:#333333; --oled-text-gold:#c9a96e;
  --oled-positive:#4a7c5f; --oled-negative:#7c4a4a; --oled-neutral:#555555;
  --oled-font-display:'Playfair Display','Georgia',serif;
  --oled-font-body:'DM Sans',ui-sans-serif,sans-serif;
  --oled-font-mono:'DM Mono','Cascadia Code',monospace;
  --oled-radius:4px; --oled-radius-card:2px;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{background:var(--oled-bg);color:var(--oled-text);font-family:var(--oled-font-body);font-size:14px;line-height:1.6;-webkit-font-smoothing:antialiased;min-height:100vh}
.page-container{max-width:1400px;margin:0 auto;padding:40px 40px 60px}
.page-header{border-bottom:1px solid var(--oled-border);padding-bottom:24px;margin-bottom:32px;display:flex;justify-content:space-between;align-items:flex-end}
.page-title{font-family:var(--oled-font-display);font-size:30px;font-weight:400;color:var(--oled-gold);letter-spacing:.03em}
.page-subtitle{font-size:11px;color:var(--oled-text-muted);letter-spacing:.2em;text-transform:uppercase;margin-top:6px}
.page-date{font-size:11px;color:var(--oled-text-muted);letter-spacing:.1em;font-family:var(--oled-font-mono)}
.layout{display:grid;grid-template-columns:250px 1fr;gap:32px}
.section-label{font-size:10px;color:var(--oled-text-muted);letter-spacing:.25em;text-transform:uppercase;margin:22px 0 8px;padding-bottom:6px;border-bottom:1px solid var(--oled-border)}
.section-label:first-child{margin-top:0}
.nav-item{display:block;width:100%;text-align:left;background:transparent;border:none;border-left:1px solid transparent;color:var(--oled-text-muted);font-family:var(--oled-font-mono);font-size:12px;padding:7px 12px;cursor:pointer;transition:all .15s;letter-spacing:.02em}
.nav-item:hover{color:var(--oled-text);background:var(--oled-surface-2)}
.nav-item.active{color:var(--oled-gold);border-left:1px solid var(--oled-gold);background:var(--oled-surface)}
.nav-item.missing{opacity:.35;font-style:italic}
.card{background:var(--oled-surface);border:1px solid var(--oled-border);border-radius:var(--oled-radius-card)}
.file-head{display:flex;justify-content:space-between;align-items:center;padding:18px 26px;border-bottom:1px solid var(--oled-border);flex-wrap:wrap;gap:12px}
.file-title{font-family:var(--oled-font-display);font-size:19px;font-weight:400;color:var(--oled-gold)}
.file-meta{font-size:11px;color:var(--oled-text-muted);font-family:var(--oled-font-mono);margin-top:3px}
.controls{display:flex;gap:10px;align-items:center}
.btn-gold{background:transparent;border:1px solid var(--oled-gold-dim);color:var(--oled-gold);font-family:var(--oled-font-body);font-size:10px;letter-spacing:.15em;text-transform:uppercase;padding:7px 16px;cursor:pointer;transition:all .2s;border-radius:var(--oled-radius)}
.btn-gold:hover{background:var(--oled-gold-muted);border-color:var(--oled-gold)}
.btn-gold.on{background:var(--oled-gold-muted);border-color:var(--oled-gold)}
pre{font-family:var(--oled-font-mono);font-size:12.5px;line-height:1.75;color:var(--oled-text);padding:24px 28px;overflow:auto;max-height:calc(100vh - 260px);white-space:pre-wrap;word-break:break-word}
.badge{font-size:10px;font-family:var(--oled-font-mono);letter-spacing:.1em;text-transform:uppercase;padding:3px 10px;border:1px solid var(--oled-border-mid);border-radius:var(--oled-radius);color:var(--oled-text-muted)}
.badge.gold{color:var(--oled-gold);border-color:var(--oled-gold-dim)}
.empty{padding:60px;text-align:center;color:var(--oled-text-muted);font-style:italic;font-family:var(--oled-font-display);font-size:15px}
@media(max-width:900px){.layout{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="page-container">
  <div class="page-header">
    <div>
      <h1 class="page-title">MCP Auth Gateway</h1>
      <p class="page-subtitle">Configuration &amp; Log Viewer</p>
    </div>
    <div class="page-date" id="clock"></div>
  </div>
  <div class="layout">
    <nav id="nav"></nav>
    <div class="card">
      <div class="file-head">
        <div>
          <div class="file-title" id="fTitle">Select a file</div>
          <div class="file-meta" id="fMeta"></div>
        </div>
        <div class="controls" id="ctl">
          <span class="badge gold" id="maskBadge" style="display:none">secrets masked</span>
          <button class="btn-gold" id="tailBtn" style="display:none">Tail 500</button>
          <button class="btn-gold" id="autoBtn" style="display:none">Auto-refresh</button>
          <button class="btn-gold" id="refreshBtn">Refresh</button>
        </div>
      </div>
      <pre id="content" class="empty">Loading manifest…</pre>
    </div>
  </div>
</div>
<script>
let manifest=[],current=null,tailMode=true,autoTimer=null;
const $=id=>document.getElementById(id);
function tick(){$("clock").textContent=new Date().toLocaleString()}
tick();setInterval(tick,1000);

async function loadManifest(){
  manifest=await (await fetch("/api/manifest")).json();
  const nav=$("nav");nav.innerHTML="";
  let group=null;
  for(const f of manifest){
    if(f.group!==group){group=f.group;const h=document.createElement("div");h.className="section-label";h.textContent=group;nav.appendChild(h);}
    const b=document.createElement("button");
    b.className="nav-item"+(f.exists?"":" missing");b.dataset.id=f.id;
    b.textContent=f.label;b.onclick=()=>select(f.id);
    nav.appendChild(b);
  }
  const first=manifest.find(f=>f.exists);
  if(first)select(first.id); else $("content").textContent="No files found.";
}

async function load(){
  if(!current)return;
  const f=manifest.find(x=>x.id===current);
  const url="/api/file/"+f.id+(f.isLog&&tailMode?"?tail=500":"");
  const d=await (await fetch(url)).json();
  if(d.error){$("content").textContent=d.error;$("fMeta").textContent="";return;}
  $("content").className="";
  $("content").textContent=d.content||"(empty file)";
  $("fMeta").textContent=d.path+"  ·  "+d.size.toLocaleString()+" bytes  ·  "+d.lines.toLocaleString()+" lines  ·  modified "+d.mtime+(d.truncated?"  ·  showing last 500 lines":"");
  if(f.isLog&&tailMode){const p=$("content");p.scrollTop=p.scrollHeight;}
}

function select(id){
  current=id;
  const f=manifest.find(x=>x.id===id);
  document.querySelectorAll(".nav-item").forEach(b=>b.classList.toggle("active",b.dataset.id===id));
  $("fTitle").textContent=f.label;
  $("maskBadge").style.display=f.masked?"":"none";
  $("tailBtn").style.display=f.isLog?"":"none";
  $("autoBtn").style.display=f.isLog?"":"none";
  if(!f.isLog&&autoTimer){clearInterval(autoTimer);autoTimer=null;$("autoBtn").classList.remove("on");}
  load();
}

$("refreshBtn").onclick=load;
$("tailBtn").onclick=()=>{tailMode=!tailMode;$("tailBtn").textContent=tailMode?"Tail 500":"Full file";load();};
$("autoBtn").onclick=()=>{
  if(autoTimer){clearInterval(autoTimer);autoTimer=null;$("autoBtn").classList.remove("on");}
  else{autoTimer=setInterval(load,5000);$("autoBtn").classList.add("on");}
};
loadManifest();
</script>
</body>
</html>
"""


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    url = f"http://{HOST}:{PORT}"
    print(f"MCP Auth Gateway viewer running at {url}  (Ctrl+C to stop)")
    threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
