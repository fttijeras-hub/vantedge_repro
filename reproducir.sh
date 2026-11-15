#!/usr/bin/env bash
# Reproducción del experimento principal del Capítulo 4 (matriz de confusión sobre 41 escenarios).
# Uso:  bash reproducir.sh            (desde la raíz del repositorio)
# Requisitos: Linux, Docker, Python 3.11+, Nuclei v3.8.0 en el PATH, plantillas nuclei-templates (commit 9e97c753).
set -euo pipefail
cd "$(dirname "$0")"
RAIZ="$(pwd)"
SALIDA="$RAIZ/salida_reproduccion"
export NUCLEI_TEMPLATES="${NUCLEI_TEMPLATES:-$HOME/nuclei-templates-git}"

echo "== 0. Comprobación de requisitos"
command -v docker >/dev/null || { echo "Falta Docker"; exit 1; }
command -v nuclei >/dev/null || { echo "Falta nuclei (v3.8.0) en el PATH"; exit 1; }
[ -d "$NUCLEI_TEMPLATES" ] || { echo "No existe NUCLEI_TEMPLATES=$NUCLEI_TEMPLATES"; exit 1; }
nuclei -version 2>&1 | grep -o 'v[0-9.]*' | head -1
git -C "$NUCLEI_TEMPLATES" log -1 --format='plantillas: %h %ci' 2>/dev/null || true

echo "== 1. Entorno de Python"
[ -d venv ] || python3 -m venv venv
./venv/bin/pip install -q -r requirements.txt

echo "== 2. Pruebas unitarias (sin red)"
./venv/bin/python -m unittest tests/test_modulo.py 2>&1 | tail -3

echo "== 3. Banco de pruebas (41 contenedores en 192.168.100.0/24)"
docker network inspect vantedge_net >/dev/null 2>&1 || docker network create --subnet=192.168.100.0/24 vantedge_net >/dev/null
python3 testbed/build_testbed.py
sleep 15   # arranque de los servicios

echo "== 4. Ejecución del motor sobre los 41 objetivos (sin Shodan)"
rm -rf "$SALIDA"; mkdir -p "$SALIDA"; cd "$SALIDA"
"$RAIZ/venv/bin/python" "$RAIZ/radar.py" --targets "$RAIZ/testbed/objetivos_testbed.json" --output-dir expedientes > radar.out 2>&1
echo "   registro: $SALIDA/auditoria_log.jsonl ($(wc -l < auditoria_log.jsonl) líneas)"

echo "== 5. Matriz de confusión y evaluación por hallazgo"
"$RAIZ/venv/bin/python" "$RAIZ/scripts/evaluar_matriz.py" auditoria_log.jsonl "$RAIZ/testbed/groundtruth.json" matriz.json
"$RAIZ/venv/bin/python" "$RAIZ/scripts/evaluar_hallazgos.py" matriz.json evaluacion_hallazgos.json

echo "== 6. Comparación con la ejecución documentada en la memoria (resultados/)"
"$RAIZ/venv/bin/python" - "$RAIZ/resultados/matriz.json" matriz.json <<'PY'
import json,sys
a=json.load(open(sys.argv[1])); b=json.load(open(sys.argv[2]))
ka={r["id"]:r["veredicto"] for r in a["escenarios"]}
kb={r["id"]:r["veredicto"] for r in b["escenarios"]}
for k in ("TP","FN","FP","TN"): print(f"   {k}: documentado={a['metricas'][k] if 'metricas' in a else a.get(k)}  reproducido={b['metricas'][k] if 'metricas' in b else b.get(k)}")
dif=[i for i in ka if ka.get(i)!=kb.get(i)]
print("   escenarios con veredicto distinto:", dif if dif else "ninguno")
PY
echo "Hecho. Para apagar el banco: docker rm -f \$(docker ps -aq --filter network=vantedge_net); docker network rm vantedge_net"
