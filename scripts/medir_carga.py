#!/usr/bin/env python3
"""Validación de carga sobre un servicio del banco de pruebas.
Un cliente legítimo sondea el servicio cada 100 ms (RTT y errores) en tres fases:
  1) línea base  2) durante la auditoría del motor sobre ese mismo servicio  3) recuperación.
Además, tcpdump contabiliza la carga que el motor ofrece al servicio (paquetes, bytes, conexiones).
Uso: medir_carga.py <ip> <puerto> <proto: modbus|s7|mqtt|http> <contenedor> <bridge>
"""
import socket, sys, time, json, subprocess, threading, statistics as st, os, signal

ip, port, proto, cont, bridge = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
FASE_S = 20
MODBUS = bytes.fromhex("000100000006010300000002")
S7_CR = bytes.fromhex("0300001611e00000000100c0010ac1020100c2020102")
MQTT_CONNECT = bytes.fromhex("100e00044d5154540402003c00027674")  # CONNECT v3.1.1 clean-session, keepalive 60, id "vt"
def probe():
    t = time.time()
    try:
        with socket.create_connection((ip, port), timeout=3) as s:
            s.settimeout(3)
            if proto == "modbus": s.sendall(MODBUS); d = s.recv(256); ok = len(d) >= 9
            elif proto == "s7": s.sendall(S7_CR); d = s.recv(256); ok = len(d) >= 7
            elif proto == "mqtt": s.sendall(MQTT_CONNECT); d = s.recv(256); ok = len(d) >= 4
            else:
                s.sendall(f"GET /web/login HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode()); d = s.recv(512); ok = d.startswith(b"HTTP")
        return time.time() - t, ok
    except OSError:
        return time.time() - t, False

fases_t = {}
fase = {"v": "base"}; muestras = {"base": [], "audit": [], "recup": []}; cpu = {"base": [], "audit": [], "recup": []}
stop = threading.Event()
def bucle():
    while not stop.is_set():
        muestras[fase["v"]].append(probe()); time.sleep(0.1)
def cpu_bucle():
    while not stop.is_set():
        r = subprocess.run(["docker", "stats", "--no-stream", "--format", "{{.CPUPerc}}", cont], capture_output=True, text=True)
        try: cpu[fase["v"]].append(float(r.stdout.strip().strip("%")))
        except ValueError: pass

pcap = f"/tmp/carga_{cont}.pcap"
tcp = subprocess.Popen(["docker", "run", "--rm", "--name", f"cap_{cont}", "--network", "host", "--cap-add=NET_ADMIN",
                        "-v", "/tmp:/pcap", "nicolaka/netshoot", "tcpdump", "-i", bridge, "-w", f"/pcap/carga_{cont}.pcap",
                        f"host {ip} and port {port} and not src host 192.168.100.250"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(3)
fases_t["base"] = [time.time(), 0]
th = [threading.Thread(target=bucle), threading.Thread(target=cpu_bucle)]
[t.start() for t in th]
time.sleep(FASE_S)
fases_t["base"][1] = time.time(); fases_t["audit"] = [time.time(), 0]
fase["v"] = "audit"
objetivo = json.dumps([{"ip": ip, "port": port, "entidad": cont}])
open("/tmp/obj_carga.json", "w").write(objetivo)
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
env = {**os.environ, "PYTHONPATH": REPO, "NUCLEI_TEMPLATES": os.environ.get("NUCLEI_TEMPLATES", os.path.expanduser("~/nuclei-templates-git"))}
t0 = time.time(); naud = 0
while time.time() - t0 < FASE_S or naud < 3:
    if os.path.exists("telemetry_cache.json"): os.remove("telemetry_cache.json")
    subprocess.run([sys.executable, os.path.join(REPO, "radar.py"), "--targets", "/tmp/obj_carga.json",
                    "--output-dir", "exp_carga", "--rate-limit", "3"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    naud += 1
t_audit = time.time() - t0
fases_t["audit"][1] = time.time(); fases_t["recup"] = [time.time(), 0]
fase["v"] = "recup"; time.sleep(FASE_S)
fases_t["recup"][1] = time.time()
stop.set(); [t.join() for t in th]
subprocess.run(["docker", "stop", f"cap_{cont}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); time.sleep(1)
txt = subprocess.run(["docker", "run", "--rm", "-v", "/tmp:/pcap", "nicolaka/netshoot", "sh", "-c",
                      f"tcpdump -tt -nn -r /pcap/carga_{cont}.pcap 2>/dev/null"], capture_output=True, text=True).stdout.splitlines()
pk = []   # (t, es_syn)
for l in txt:
    try: t = float(l.split()[0])
    except (ValueError, IndexError): continue
    pk.append((t, " [S]," in l or "Flags [S]," in l))
def ventana(f):
    a_, b_ = fases_t[f]
    sel = [x for x in pk if a_ <= x[0] < b_]
    return {"paquetes": len(sel), "syn": sum(1 for x in sel if x[1]), "segundos": round(b_ - a_, 1)}
def resumen(f):
    m = muestras[f]; rtt = [x[0]*1000 for x in m]; err = sum(1 for x in m if not x[1])
    rtt_ok = [x[0]*1000 for x in m if x[1]]
    q = lambda p: (sorted(rtt_ok)[min(len(rtt_ok)-1, int(p*len(rtt_ok)))] if rtt_ok else None)
    return {"n": len(m), "errores": err, "rtt_p50_ms": round(q(0.5), 2) if rtt_ok else None,
            "rtt_p95_ms": round(q(0.95), 2) if rtt_ok else None, "rtt_max_ms": round(max(rtt_ok), 2) if rtt_ok else None,
            "cpu_media_pct": round(st.mean(cpu[f]), 2) if cpu[f] else None, "cpu_max_pct": max(cpu[f]) if cpu[f] else None}
vb, va = ventana("base"), ventana("audit")
tasa_base = vb["paquetes"] / vb["segundos"]
extra_pk = va["paquetes"] - tasa_base * va["segundos"]
res = {"servicio": cont, "ip": ip, "puerto": port, "proto": proto, "auditorias_ejecutadas": naud, "duracion_fase_auditoria_s": round(t_audit, 1),
       "fases": {f: resumen(f) for f in muestras},
       "trafico": {"base": vb, "audit": va, "recup": ventana("recup"),
                   "paquetes_extra_por_auditoria_motor": round(extra_pk / naud, 1)}}
json.dump(res, open(f"carga_{cont}.json", "w"), indent=1)
print(json.dumps(res, indent=1))
