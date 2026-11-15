#!/usr/bin/env python3
"""Tiempo de máquina por activo medido con la función auditar_activo() del módulo entregado.
Repite cada tipo de escenario n veces y emite media, desviación típica (muestral) y n."""
import json, sys, time, statistics as st, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import modulos_software_tfg as m
N = int(sys.argv[1]) if len(sys.argv) > 1 else 10
gt = {s["id"]: s for s in json.load(open(sys.argv[2] if len(sys.argv) > 2 else "groundtruth.json"))}
casos = {"Odoo vulnerable (HTTP+L7)": "P-ODOO-01", "Odoo endurecido (HTTP+L7)": "N-ODOO-01",
         "HTTP plano": "N-HTTP-01", "Modbus TCP": "P-MODBUS-01", "S7comm": "P-S7-01",
         "MQTT anónimo": "P-MQTT-01", "MQTT con autenticación": "N-MQTT-01",
         "Puerto 502 abierto sin Modbus": "N-MBCLOSED-01"}
cfg = {**m.CONFIG_POR_DEFECTO, "nuclei_templates": os.environ.get("NUCLEI_TEMPLATES", ""), "log_jsonl": "tiempos_log.jsonl",
       "nuclei_bin": "nuclei"}
res = {}
for nombre, id_ in casos.items():
    s = gt[id_]; ts = []
    for _ in range(N):
        r = m.auditar_activo(s["ip"], s["port"], id_, "exp_tiempos", cfg)
        ts.append(r["t_total_s"])
    res[nombre] = {"escenario": id_, "n": N, "media_s": round(st.mean(ts), 2),
                   "desv_s": round(st.stdev(ts), 2) if N > 1 else 0.0, "min_s": min(ts), "max_s": max(ts)}
    print(f"{nombre:34s} n={N} media={res[nombre]['media_s']}s desv={res[nombre]['desv_s']}s [{min(ts)}..{max(ts)}]", flush=True)
json.dump(res, open("tiempos_modulo.json", "w"), indent=1, ensure_ascii=False)
