#!/bin/bash
# Compara el tráfico de varias CONFIGURACIONES de auditoría web sobre el MISMO objetivo, con captura tcpdump.
# Uso: medir_configuraciones_web.sh <ip> <puerto> <repeticiones> <dir_salida>
# Configuraciones:
#   completa    : pasada HTTP del módulo (tags panel,exposure,misconfig; severidad critical,high; 716 plantillas)
#   dirigida    : una sola plantilla (odoo-unprotected-database), una petición HTTP por diseño de la plantilla
#   l7_propio   : solo la verificación de la capa de aplicación del propio motor (sin Nuclei)
#   referencia  : dos peticiones HTTP de un cliente normal (carga de la raíz y de la ruta del gestor)
IP=${1:-192.168.100.11}; PORT=${2:-8069}; REPS=${3:-5}; OUT=${4:-./configuraciones_web}
T=${NUCLEI_TEMPLATES:-$HOME/nuclei-templates-git}
REPO=${REPO:-$(cd "$(dirname "$0")/.." && pwd)}
PY=${PYTHON:-python3}
# Ruta absoluta del intérprete: el script cambia de directorio antes de usarlo
PY=$(command -v "$PY" 2>/dev/null || echo "$PY"); case "$PY" in /*) ;; *) PY="$(pwd)/$PY";; esac
mkdir -p "$OUT"; cd "$OUT"
BR=br-$(docker network inspect vantedge_net -f '{{.Id}}' | cut -c1-12)
tc(){ docker run --rm -v "$PWD":/pcap nicolaka/netshoot sh -c "$1"; }
cuenta(){ tc "tcpdump -nn -r /pcap/$1 2>/dev/null | wc -l"; }
syns(){ tc "tcpdump -nn -r /pcap/$1 'tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn' 2>/dev/null | wc -l"; }
bytes(){ tc "ls -l /pcap/$1 | awk '{print \$5}'"; }
run_cfg(){ # $1 nombre, $2 rep, resto: comando
  local n=$1 r=$2; shift 2
  docker run -d --rm --name capx --network host --cap-add=NET_ADMIN -v "$PWD":/pcap nicolaka/netshoot \
    tcpdump -i "$BR" -w /pcap/${n}_$r.pcap host $IP >/dev/null 2>&1
  sleep 2
  local t0=$(date +%s.%N)
  "$@" < /dev/null > ${n}_$r.log 2>&1
  local t1=$(date +%s.%N)
  sleep 1; docker stop capx >/dev/null 2>&1; sleep 1
  local d=$(python3 -c "print(round($t1-$t0,2))")
  echo "$n,$r,$d,$(cuenta ${n}_$r.pcap),$(syns ${n}_$r.pcap),$(bytes ${n}_$r.pcap)" >> filas.csv
  echo "$n rep $r: ${d}s paquetes=$(tail -1 filas.csv | cut -d, -f4) conexiones=$(tail -1 filas.csv | cut -d, -f5)"
}
echo "config,rep,duracion_s,paquetes,conexiones_syn,bytes_pcap" > filas.csv
for i in $(seq 1 $REPS); do
  run_cfg completa $i nuclei -u $IP:$PORT -t $T -tags panel,exposure,misconfig -severity critical,high -mhe 3 -timeout 3 -ni -duc -silent -o /dev/null
  run_cfg dirigida $i nuclei -u $IP:$PORT -t $T/http/misconfiguration/odoo-unprotected-database.yaml -timeout 3 -ni -duc -silent -o /dev/null
  run_cfg l7_propio $i env PYTHONPATH=$REPO $PY -c "import modulos_software_tfg as m; print(m.verificar_integridad_endpoints_l7('$IP',$PORT))"
  run_cfg referencia $i sh -c "curl -s -o /dev/null http://$IP:$PORT/ ; curl -s -o /dev/null http://$IP:$PORT/web/database/manager"
done
python3 - <<'PY' | tee resumen.txt
import csv, statistics as st, collections
d = collections.defaultdict(list)
for r in csv.DictReader(open("filas.csv")): d[r["config"]].append(r)
print("config,n,paquetes_media,paquetes_desv,conexiones_media,duracion_media_s,paquetes_por_s")
for k, rs in d.items():
    p = [int(x["paquetes"]) for x in rs]; c = [int(x["conexiones_syn"]) for x in rs]; t = [float(x["duracion_s"]) for x in rs]
    print(f"{k},{len(rs)},{st.mean(p):.0f},{(st.stdev(p) if len(p)>1 else 0):.0f},{st.mean(c):.1f},{st.mean(t):.2f},{(st.mean(p)/st.mean(t) if st.mean(t) > 0 else 0):.0f}")
PY
