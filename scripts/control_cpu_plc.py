#!/usr/bin/env python3
"""Control positivo de sensibilidad del método: se priva de CPU al contenedor del PLC (límite de CPU + procesos
ocupados dentro del contenedor) y se comprueba que el contador de ciclos SÍ detecta la degradación.
Uso: control_cpu_plc.py <ip> <puerto> <contenedor> <salida.json>"""
import socket, sys, time, json, subprocess, os, statistics as st
ip, port, cont, salida = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
REQ = bytes.fromhex("000100000006010300000001")
s = socket.create_connection((ip, port), timeout=3); s.settimeout(3)
def leer():
    s.sendall(REQ); d = s.recv(64); return time.time(), int.from_bytes(d[9:11], "big")
def fase(dur):
    m = []; t0 = time.time()
    while time.time() - t0 < dur:
        try: m.append(leer())
        except OSError: pass
        time.sleep(0.1)
    vent = []; i = 0
    while i < len(m):
        j = i
        while j + 1 < len(m) and m[j + 1][0] - m[i][0] < 5.0: j += 1
        dt = m[j][0] - m[i][0]
        if dt >= 4.0: vent.append(((m[j][1] - m[i][1]) % 65536) / dt)
        i = j + 1
    return {"lecturas": len(m), "ventanas_5s": len(vent), "ciclos_por_s_ventana_media": round(st.mean(vent), 2) if vent else None,
            "ciclos_por_s_ventana_min": round(min(vent), 2) if vent else None}
res = {"base": fase(15)}
subprocess.run(["docker", "update", "--cpus", "0.2", cont], capture_output=True)
bur = subprocess.Popen(["docker", "exec", cont, "sh", "-c", "for i in 1 2 3 4; do (timeout 16 sh -c 'while :; do :; done' &) ; done; sleep 16"])
res["privado_de_cpu"] = fase(15)
bur.wait(); subprocess.run(["docker", "update", "--cpus", str(os.cpu_count()), cont], capture_output=True)  # sin límite efectivo
res["recuperacion"] = fase(15)
json.dump(res, open(salida, "w"), indent=1); print(json.dumps(res, indent=1))
