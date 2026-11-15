"""Calcula la matriz de confusión comparando auditoria_log.jsonl (salida del motor) con groundtruth.json
(verdad de referencia fijada por construcción del banco, anterior e independiente del escaneo)."""
import json, sys, math
def wilson(k, n, z=1.96):
    if n == 0: return (0.0, 0.0)
    p = k/n; d = 1+z*z/n; c = p+z*z/(2*n); r = z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))
    return (100*(c-r)/d, 100*(c+r)/d)
def main(log, gt, out):
    g = {s["id"]: s for s in json.load(open(gt))}
    reg = {}
    for l in open(log):
        r = json.loads(l)
        if "entidad" in r: reg[r["entidad"]] = r
    rows = []
    for id_, s in g.items():
        r = reg.get(id_)
        det = bool(r and r["detectado"]); v = s["vulnerable"]
        ver = "TP" if v and det else "FN" if v and not det else "FP" if (not v) and det else "TN"
        rows.append({"id": id_, "ip": s["ip"], "port": s["port"], "tipo": s["kind"], "vulnerable": v,
                     "verdad_referencia": s["ground_truth"], "detectado": det,
                     "hallazgos": r["hallazgos"] if r else [], "t_total_s": r["t_total_s"] if r else None,
                     "veredicto": ver})
    c = {k: sum(x["veredicto"] == k for x in rows) for k in ("TP", "FN", "FP", "TN")}
    N = len(rows)
    m = {**c, "N": N,
         "exactitud": 100*(c["TP"]+c["TN"])/N,
         "sensibilidad": 100*c["TP"]/(c["TP"]+c["FN"]),
         "precision": 100*c["TP"]/(c["TP"]+c["FP"]) if c["TP"]+c["FP"] else None,
         "fpr": 100*c["FP"]/(c["FP"]+c["TN"]),
         "especificidad": 100*c["TN"]/(c["TN"]+c["FP"]),
         "ic95_sensibilidad": wilson(c["TP"], c["TP"]+c["FN"]),
         "ic95_fpr": wilson(c["FP"], c["FP"]+c["TN"]),
         "ic95_exactitud": wilson(c["TP"]+c["TN"], N),
         "ic95_precision": wilson(c["TP"], c["TP"]+c["FP"]),
         "ic95_especificidad": wilson(c["TN"], c["TN"]+c["FP"])}
    p, rcl = m["precision"]/100, m["sensibilidad"]/100
    m["f1"] = 2*p*rcl/(p+rcl)
    json.dump({"metricas": m, "escenarios": rows}, open(out, "w"), indent=1, ensure_ascii=False)
    print(json.dumps(m, indent=1))
    for x in rows:
        print(f"{x['id']:14s} v={int(x['vulnerable'])} det={int(x['detectado'])} {x['veredicto']} {x['t_total_s']} {x['hallazgos'][:2]}")
if __name__ == "__main__":
    main(*sys.argv[1:4])
