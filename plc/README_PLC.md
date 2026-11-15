# PLC software del banco de pruebas (OpenPLC v3)
Origen: https://github.com/thiagoralves/OpenPLC_v3 (commit b5d41356dab4aeadca0dd7ca64ba542f870b595d).
Construcción: `docker build -t openplc:v3 .` en el repositorio de OpenPLC (Dockerfile incluido como OpenPLC.Dockerfile).
Nota: la interfaz web no se usa; se compila el programa con `scripts/compile_program.sh contador.st` dentro del contenedor y se
arranca `core/openplc`, enviando `start_modbus(502)` al puerto local 43628.

```bash
docker network create --subnet=192.168.100.0/24 vantedge_net   # si no existe
docker run -d --name plc_openplc --network vantedge_net --ip 192.168.100.60 --entrypoint sleep openplc:v3 infinity
docker cp plc/contador.st plc_openplc:/workdir/webserver/st_files/contador.st
docker exec -w /workdir/webserver plc_openplc bash scripts/compile_program.sh contador.st
docker exec -d -w /workdir/webserver/core plc_openplc ./openplc
docker exec plc_openplc python3 -c "import socket;s=socket.create_connection(('127.0.0.1',43628));s.sendall(b'start_modbus(502)\n');print(s.recv(50))"
python3 scripts/medir_ciclo_plc.py 192.168.100.60 502 plc_run1.json      # usar el python del entorno virtual del motor
python3 scripts/control_cpu_plc.py 192.168.100.60 502 plc_openplc control_cpu_1.json
```
