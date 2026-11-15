#!/bin/bash
cd /home/claude/work/final/plc || exit 1
PY=/home/claude/work/venv/bin/python3
docker update --cpus $(nproc) plc_openplc >/dev/null
echo "NanoCpus=$(docker inspect plc_openplc -f '{{.HostConfig.NanoCpus}}') (limite de CPU del contenedor del PLC antes de medir)" > estado_cpu.txt
for i in 1 2 3; do
  $PY /home/claude/work/repo/scripts/medir_ciclo_plc.py 192.168.100.60 502 plc_run$i.json > plc_run$i.log 2>&1
done
for i in 1 2 3; do
  $PY /home/claude/work/repo/scripts/control_cpu_plc.py 192.168.100.60 502 plc_openplc control_cpu_$i.json > control_cpu_$i.log 2>&1
done
echo "NanoCpus final=$(docker inspect plc_openplc -f '{{.HostConfig.NanoCpus}}')" >> estado_cpu.txt
date -Iseconds > FIN
