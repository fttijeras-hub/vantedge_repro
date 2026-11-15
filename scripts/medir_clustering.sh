#!/bin/bash
# Reducción REAL de tráfico por Template Clustering: captura tcpdump con y sin clustering sobre el MISMO
# objetivo y el MISMO conjunto de plantillas. Uso: medir_clustering.sh <ip> <puerto> <repeticiones> <dir_salida>
IP=${1:-192.168.100.11}; PORT=${2:-8069}; REPS=${3:-5}; OUT=${4:-./clustering}
T=${NUCLEI_TEMPLATES:-$HOME/nuclei-templates-git}
mkdir -p "$OUT"; cd "$OUT"
BR=br-$(docker network inspect vantedge_net -f '{{.Id}}' | cut -c1-12)
TS="-t $T -tags panel,exposure,misconfig -severity critical,high -mhe 3"
pk(){ docker run --rm -v "$PWD":/pcap nicolaka/netshoot sh -c "tcpdump -nn -r /pcap/$1 2>/dev/null | wc -l"; }
by(){ docker run --rm -v "$PWD":/pcap nicolaka/netshoot sh -c "ls -l /pcap/$1 | awk '{print \$5}'"; }
run_one(){ # $1 = flags extra, $2 = nombre pcap
  docker run -d --rm --name capx --network host --cap-add=NET_ADMIN -v "$PWD":/pcap nicolaka/netshoot \
    tcpdump -i "$BR" -w /pcap/$2 host $IP >/dev/null 2>&1
  sleep 2
  nuclei -u $IP:$PORT $TS -timeout 3 -ni -duc $1 -silent -stats -si 5 -o /dev/null < /dev/null > $2.log 2>&1
  docker stop capx >/dev/null 2>&1; sleep 1
}
echo "rep,paquetes_con,paquetes_sin,bytes_con,bytes_sin,reduccion_paquetes_pct" > reps.csv
for i in $(seq 1 $REPS); do
  run_one "" rc$i.pcap; run_one "-disable-clustering" rs$i.pcap
  C=$(pk rc$i.pcap); S=$(pk rs$i.pcap); BC=$(by rc$i.pcap); BS=$(by rs$i.pcap)
  R=$(python3 -c "print(round(100*($S-$C)/$S,2) if $S else 0)")
  echo "$i,$C,$S,$BC,$BS,$R" >> reps.csv; echo "rep $i: con=$C sin=$S reduccion=$R%"
done
python3 - <<'PY' | tee resumen.txt
import csv, statistics as st
r = [float(x["reduccion_paquetes_pct"]) for x in csv.DictReader(open("reps.csv"))]
print(f"REDUCCION media={st.mean(r):.2f}% desv_muestral={st.stdev(r) if len(r)>1 else 0:.2f}% n={len(r)} valores={r}")
PY
