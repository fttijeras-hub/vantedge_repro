#!/usr/bin/env python3
"""Efecto de la auditoría sobre el CICLO DE EJECUCIÓN de un PLC software (OpenPLC).
El programa del PLC (ver plc/contador.st) incrementa un contador UINT en cada ciclo de una tarea
periódica de 10 ms y lo expone en el registro de retención 0 (%QW0). Un cliente Modbus legítimo lo lee
cada 100 ms por una conexión persistente (como haría un SCADA). Si el PLC ejecuta sus ciclos a tiempo, el contador avanza ~10 unidades por lectura
(100 ciclos/s). Se miden cuatro fases: 1) línea base, 2) auditoría del motor sobre el mismo PLC,
3) recuperación, 4) control positivo: carga deliberada de conexiones Modbus (comprueba que el método
sería capaz de detectar una degradación).
Uso: medir_ciclo_plc.py <ip> <puerto> <salida.json>
"""
import socket, sys, time, json, subprocess, threading, statistics as st, os

ip, port, salida = sys.argv[1], int(sys.argv[2]), sys.argv[3]
FASE_S = 30
REQ = bytes.fromhex("000100000006010300000001")   # leer 1 registro de retención en la dirección 0
TICK_S = 0.010

conn = {"s": None}
def conectar():
    try:
        if conn["s"]: conn["s"].close()
    except OSError: pass
    conn["s"] = socket.create_connection((ip, port), timeout=3); conn["s"].settimeout(3)

def leer():
    """Lectura por una conexión persistente. La marca de tiempo es la de RECEPCIÓN de la respuesta
    (el contador se lee justo antes de responder), lo que evita el error de medida de la espera de aceptación."""
    t = time.time()
    try:
        if conn["s"] is None: conectar()
        conn["s"].sendall(REQ); d = conn["s"].recv(64)
        t2 = time.time()
        if len(d) >= 11 and d[7] == 3:
            return t2, int.from_bytes(d[9:11], "big"), t2 - t
    except OSError:
        conn["s"] = None
    return time.time(), None, time.time() - t

fase = {"v": "base"}; datos = {k: [] for k in ("base", "audit", "recup", "control")}
stop = threading.Event()
def poller():
    while not stop.is_set():
        datos[fase["v"]].append(leer()); time.sleep(0.1)

def estres(dur):
    fin = time.time() + dur
    def w():
        while time.time() < fin:
            try:
                with socket.create_connection((ip, port), timeout=1) as s:
                    s.sendall(REQ); s.recv(64)
            except OSError: pass
    hs = [threading.Thread(target=w) for _ in range(40)]
    [h.start() for h in hs]; [h.join() for h in hs]

conectar()
th = threading.Thread(target=poller); th.start()
time.sleep(FASE_S)                                   # 1) línea base
fase["v"] = "audit"
open("/tmp/obj_plc.json", "w").write(json.dumps([{"ip": ip, "port": port, "entidad": "plc-openplc"}]))
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
env = {**os.environ, "PYTHONPATH": REPO, "NUCLEI_TEMPLATES": os.environ.get("NUCLEI_TEMPLATES", os.path.expanduser("~/nuclei-templates-git"))}
t0 = time.time(); naud = 0; hall = []
while time.time() - t0 < FASE_S or naud < 3:         # 2) auditoría (≥3 repeticiones completas del motor)
    if os.path.exists("telemetry_cache.json"): os.remove("telemetry_cache.json")
    subprocess.run([sys.executable, os.path.join(REPO, "radar.py"), "--targets", "/tmp/obj_plc.json",
                    "--output-dir", "exp_plc", "--rate-limit", "3"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    naud += 1
    if os.path.exists("auditoria_log.jsonl"):
        hall = [json.loads(l).get("hallazgos") for l in open("auditoria_log.jsonl") if '"hallazgos"' in l][-1:]
fase["v"] = "recup"; time.sleep(FASE_S)              # 3) recuperación
fase["v"] = "control"; estres(FASE_S // 2)           # 4) control positivo
stop.set(); th.join()

def resumen(m):
    ok = [x for x in m if x[1] is not None]
    # ciclos por segundo en ventanas de 5 s (cada ventana: ~500 ciclos esperados; el error de ±1 ciclo es < 0,2 %)
    vent, i = [], 0
    while i < len(ok):
        j = i
        while j + 1 < len(ok) and ok[j + 1][0] - ok[i][0] < 5.0: j += 1
        dt = ok[j][0] - ok[i][0]
        if dt >= 4.0:
            vent.append(((ok[j][1] - ok[i][1]) % 65536) / dt)
        i = j + 1
    rtt = sorted(x[2] for x in ok)
    tot_dt = (ok[-1][0] - ok[0][0]) if len(ok) > 1 else 0
    tot_c = sum(((b[1] - a[1]) % 65536) for a, b in zip(ok, ok[1:]))
    return {"lecturas": len(m), "errores": len(m) - len(ok),
            "ciclos_por_s_global": round(tot_c / tot_dt, 3) if tot_dt else None,
            "ventanas_5s": len(vent),
            "ciclos_por_s_ventana_media": round(st.mean(vent), 3) if vent else None,
            "ciclos_por_s_ventana_desv": round(st.pstdev(vent), 3) if len(vent) > 1 else None,
            "ciclos_por_s_ventana_min": round(min(vent), 3) if vent else None,
            "ciclos_por_s_ventana_max": round(max(vent), 3) if vent else None,
            "rtt_ms_mediana": round(1000 * st.median(rtt), 2) if rtt else None,
            "rtt_ms_p99": round(1000 * rtt[int(0.99 * (len(rtt) - 1))], 2) if rtt else None,
            "rtt_ms_max": round(1000 * rtt[-1], 2) if rtt else None}
res = {k: resumen(v) for k, v in datos.items()}
res["auditorias_completas"] = naud; res["fase_s"] = FASE_S; res["tick_ms"] = TICK_S * 1000
json.dump(res, open(salida, "w"), indent=1)
json.dump({k: [[round(x[0], 3), x[1], round(x[2], 4)] for x in v] for k, v in datos.items()}, open(salida.replace(".json", "_crudo.json"), "w"))
print(json.dumps(res, indent=1))
