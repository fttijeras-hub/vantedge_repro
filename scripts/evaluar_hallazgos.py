"""Reanálisis a nivel de HALLAZGO de la campaña de 41 escenarios (complementa evaluar_matriz.py, que evalúa a nivel de activo).
Uso: python3 evaluar_hallazgos.py <matriz.json> <salida.json>

Criterio (definido a posteriori, a partir de la descripción de la verdad de referencia de cada tipo de escenario):
  - hallazgo VÁLIDO: el identificador informado corresponde a la exposición descrita en la verdad de referencia;
  - hallazgo ESPERADO: cada detector independiente que debería informar la exposición (en Odoo vulnerable hay dos:
    la plantilla de Nuclei y la verificación L7 propia).
"""
import json, math, sys, collections

VALIDOS = {  # tipo de escenario -> hallazgos válidos (= esperados)
    "odoo_vuln": {"l7-odoo-unprotected", "odoo-unprotected-database"},
    "odoo_slow": {"l7-odoo-unprotected", "odoo-unprotected-database"},
    "modbus": {"modbus-detect"},
    "s7": {"siemens-s7-detect"},
    "mqtt_anon": {"unauth-mqtt-broker"},
}  # los tipos endurecidos/negativos no tienen hallazgos válidos

def wilson(k, n, z=1.96):
    if n == 0: return (0.0, 0.0)
    p = k / n; d = 1 + z * z / n; c = p + z * z / (2 * n); r = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (100 * (c - r) / d, 100 * (c + r) / d)

def main(matriz, salida):
    esc = json.load(open(matriz))["escenarios"]
    informados = validos = esperados = encontrados = 0
    falsos = collections.Counter()
    for e in esc:
        v = VALIDOS.get(e["tipo"], set())
        h = set(e["hallazgos"])
        informados += len(h); validos += len(h & v)
        esperados += len(v); encontrados += len(h & v)
        for x in h - v: falsos[(e["tipo"], x)] += 1
    activo_ok = sum(e["veredicto"] in ("TP", "TN") for e in esc)
    out = {
        "activo": {"aciertos": activo_ok, "n": len(esc), "pct": 100 * activo_ok / len(esc), "ic95": wilson(activo_ok, len(esc))},
        "hallazgo_precision": {"validos": validos, "informados": informados, "pct": 100 * validos / informados, "ic95": wilson(validos, informados)},
        "hallazgo_cobertura": {"encontrados": encontrados, "esperados": esperados, "pct": 100 * encontrados / esperados, "ic95": wilson(encontrados, esperados)},
        "hallazgos_no_validos": {f"{t}:{h}": n for (t, h), n in falsos.items()},
        "servidor_real_openplc": {"detectado": 3, "auditorias": 12, "pct": 100 * 3 / 12, "ic95": wilson(3, 12)},
    }
    json.dump(out, open(salida, "w"), indent=1, ensure_ascii=False)
    print(json.dumps(out, indent=1, ensure_ascii=False))

if __name__ == "__main__":
    main(*sys.argv[1:3])
