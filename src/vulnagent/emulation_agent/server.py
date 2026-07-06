"""Emulation Agent — QEMU firmware emulation REST API server.

Start: python3 -m uvicorn server:app --host 0.0.0.0 --port 9100
Deploy: bash deploy.sh (see deploy.sh for SSH config)
"""
from __future__ import annotations

import hashlib, json, os, shutil, signal, subprocess, time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

WORK_ROOT = Path(os.environ.get("EMULATION_ROOT", "/tmp/emulation_agent"))
QEMU_MAP = {"mips_little":"qemu-mipsel-static","mips_big":"qemu-mips-static",
            "arm_little":"qemu-arm-static","aarch64_little":"qemu-aarch64-static"}

@dataclass
class EmulatedService:
    service_id: str; binary_name: str; binary_path: str
    architecture: str; rootfs_id: str; port: int; command: list[str]
    pid: int=0; status: str="stopped"; started_at: float=0.0
    def as_dict(self)->dict: return {"service_id":self.service_id,"binary_name":self.binary_name,"architecture":self.architecture,"port":self.port,"status":self.status,"pid":self.pid,"command":" ".join(self.command)}

@dataclass
class RootfsEntry:
    rootfs_id: str; path: Path; architecture: str="unknown"; endianness: str="unknown"
    def as_dict(self)->dict: return {"rootfs_id":self.rootfs_id,"path":str(self.path),"architecture":self.architecture,"endianness":self.endianness}

_rootfs: dict[str,RootfsEntry] = {}
_svcs: dict[str,EmulatedService] = {}
_procs: dict[str,subprocess.Popen] = {}

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
app = FastAPI(title="Emulation Agent", version="1.0.0")
WORK_ROOT.mkdir(parents=True,exist_ok=True); (WORK_ROOT/"rootfs").mkdir(exist_ok=True)

@app.get("/api/health")
async def health():
    running = sum(1 for s in _svcs.values() if s.status=="running")
    return {"status":"ok","binaries":{a:shutil.which(b)is not None for a,b in QEMU_MAP.items()},"services_running":running,"rootfs_count":len(_rootfs)}

@app.post("/api/upload_rootfs")
async def upload_rootfs(file: UploadFile=File(...)):
    rid = hashlib.sha256(file.filename.encode()).hexdigest()[:16]
    dest = WORK_ROOT/"rootfs"/rid
    if dest.exists(): shutil.rmtree(dest)
    dest.mkdir(parents=True)
    tmp = WORK_ROOT/f"up_{rid}.tar.gz"; tmp.write_bytes(await file.read())
    try: subprocess.run(["tar","xzf",str(tmp),"-C",str(dest)],check=True,timeout=60)
    except Exception as e: return {"error":f"extract:{e}"}
    finally: tmp.unlink(missing_ok=True)
    arch,endian = _detect_arch(dest)
    _rootfs[rid] = RootfsEntry(rid,dest,arch,endian)
    return _rootfs[rid].as_dict()

@app.post("/api/start_service")
async def start_service(rootfs_id: str=Form(...), binary_path: str=Form(...), binary_name: str=Form(...), args: str=Form(""), port: int=Form(...)):
    e = _rootfs.get(rootfs_id)
    if not e: raise HTTPException(404,"rootfs not found")
    arch_key = f"{e.architecture}_{e.endianness}"
    qemu = QEMU_MAP.get(arch_key)
    if not qemu or not shutil.which(qemu): raise HTTPException(500,f"QEMU missing: {qemu}")
    sid = hashlib.sha256(f"{rootfs_id}:{binary_path}:{port}".encode()).hexdigest()[:12]
    _kill_port(port)
    full = e.path / binary_path.lstrip("/")
    cmd = [qemu,"-L",str(e.path),str(full)] + (args.split() if args else [])
    from subprocess import DEVNULL, PIPE
    proc = subprocess.Popen(cmd, stdout=DEVNULL, stderr=PIPE, preexec_fn=os.setsid)
    svc = EmulatedService(sid,binary_name,binary_path,arch_key,rootfs_id,port,cmd,proc.pid,"starting",time.time())
    _svcs[sid]=svc; _procs[sid]=proc
    time.sleep(1.5); svc.status="running" if proc.poll() is None else "crashed"
    return svc.as_dict()

@app.post("/api/stop_service/{sid}")
async def stop_service(sid: str):
    svc = _svcs.get(sid)
    if not svc: raise HTTPException(404)
    proc = _procs.pop(sid,None)
    if proc and proc.poll() is None:
        try: os.killpg(os.getpgid(proc.pid),signal.SIGTERM); proc.wait(timeout=5)
        except Exception: proc.kill()
    svc.status="stopped"; return svc.as_dict()

@app.get("/api/status")
async def get_status():
    return {"rootfs":{r: v.as_dict() for r,v in _rootfs.items()},"services":{s: v.as_dict() for s,v in _svcs.items()}}

@app.post("/api/probe")
async def probe(host: str=Form("127.0.0.1"), port: int=Form(...), protocol: str=Form("tcp")):
    import socket
    r = {"reachable":False,"port":port,"protocol":protocol}
    try: s=socket.socket(); s.settimeout(3); s.connect((host,port)); s.close(); r["reachable"]=True
    except: pass
    if protocol=="http" and r["reachable"]:
        import urllib.request
        try: resp=urllib.request.urlopen(f"http://{host}:{port}/",timeout=3); r["http_status"]=resp.status
        except: pass
    if protocol=="telnet" and r["reachable"]:
        try: s=socket.socket(); s.settimeout(3); s.connect((host,port)); time.sleep(0.3); d=s.recv(256); s.close(); r["telnet_banner"]=d[:50].hex()
        except: pass
    return r

@app.post("/api/exec")
async def exec_command(rootfs_id: str=Form(...), command: str=Form(...), timeout: int=Form(10)):
    e = _rootfs.get(rootfs_id)
    if not e: raise HTTPException(404)
    qemu = QEMU_MAP.get(f"{e.architecture}_{e.endianness}")
    if not qemu: raise HTTPException(400,f"unsupported: {e.architecture}")
    try:
        bb = str(e.path/"bin"/"busybox")
        p = subprocess.run([qemu,"-L",str(e.path),bb,"sh","-c",command],capture_output=True,text=True,timeout=timeout)
        return {"rc":p.returncode,"stdout":p.stdout[:4096],"stderr":p.stderr[:2048]}
    except subprocess.TimeoutExpired: return {"rc":-1,"stdout":"","stderr":f"timeout {timeout}s"}

@app.post("/api/nvram_config")
async def nvram_config(rootfs_id: str=Form(...), config_json: str=Form("{}")):
    e = _rootfs.get(rootfs_id)
    if not e: raise HTTPException(404)
    cfg = json.loads(config_json)
    p = e.path/"etc_ro"/"nvram.conf"; p.parent.mkdir(parents=True,exist_ok=True)
    p.write_text("\n".join(f"{k}={v}" for k,v in cfg.items())); return {"status":"ok","entries":len(cfg)}

def _kill_port(port: int):
    for sid,svc in list(_svcs.items()):
        if svc.port == port:
            proc = _procs.pop(sid,None)
            if proc:
                try: os.killpg(os.getpgid(proc.pid),signal.SIGKILL)
                except: pass
            del _svcs[sid]

def _detect_arch(rootfs: Path)->tuple[str,str]:
    for f in list(rootfs.rglob("bin/busybox"))[:1]:
        try:
            b = f.read_bytes()[:64]
            if b[:4]!=b"\x7fELF": continue
            m = {8:"mips",40:"arm",183:"aarch64",3:"i386",62:"x86_64"}
            return m.get(b[18],"unknown"), ("little" if b[5]==1 else "big")
        except: continue
    return "unknown","unknown"


# ═══════════════════════════════════════════════════════════════════
# Openclaw Bridge — see EMULATION_AGENT_SPEC.md for protocol details
# ═══════════════════════════════════════════════════════════════════
# Emu Agent subscribes to:  channel "scan_requests"  → receives {vendor,model,targets,firmware_url}
# Emu Agent publishes to:   channel "env_ready"       → sends {task_id,services,endpoints,rootfs_path}
# vulnagent subscribes to:  channel "env_ready"       → receives emulation config
# vulnagent publishes to:   channel "scan_requests"   → sends scan target assignment
# All via openclaw bound to 127.0.0.1 — no external network exposure
