# vantedge_repro — Repositorio de reproducción del TFG «Vantedge Risk Engine»

Código, banco de pruebas y scripts de medida con los que se obtuvieron los resultados del Capítulo 4 de la memoria
(Francisco Javier Tijeras Mena, Grado en Ingeniería Electrónica Industrial, Universidad de Granada, 2026).

> **Uso exclusivo en laboratorio.** Todos los experimentos se ejecutan contra contenedores locales en la red aislada
> `vantedge_net` (192.168.100.0/24). No ejecute el motor contra sistemas de terceros sin su autorización escrita.

## 1. Estructura

| Ruta | Contenido |
| --- | --- |
| `modulos_software_tfg.py` | Motor: núcleo de control y estado, inspección L7, filtrado, pasadas OT/HTTP, Módulos 4 y 5 (no integrados) |
| `radar.py` | Punto de entrada por línea de comandos (`--targets` para auditar una lista cerrada sin Shodan) |
| `requirements.txt` | Dependencias de Python con versión fija |
| `reproducir.sh` | Reproduce el experimento principal (pasos 0–6 de la sección 3) y lo compara con `resultados/` |
| `tests/test_modulo.py` | 8 pruebas unitarias (sin red ni Docker) |
| `testbed/` | `build_testbed.py` (41 contenedores), `groundtruth.json` (verdad de referencia), `objetivos_testbed.json`, simuladores y configuraciones |
| `scripts/` | Evaluación (matriz, hallazgos) y medidas (tiempos, carga, *clustering*, configuraciones web, ciclo del PLC) |
| `plc/` | Programa ST del PLC, Dockerfile y pasos de OpenPLC (`README_PLC.md`) |
| `resultados/` | Ejecución documentada en la memoria (28/10/2026 y 04/11/2026): registros, JSON, PCAP y capturas |

## 2. Requisitos

- Linux x86-64 con Docker (probado con Docker 29.9.1) y permisos para crear redes y contenedores.
- Python 3.11 o superior (probado con 3.13.16).
- Nuclei v3.8.0 en el `PATH` y las plantillas en la revisión usada en la memoria:

```bash
curl -sSL -o nuclei.zip https://github.com/projectdiscovery/nuclei/releases/download/v3.8.0/nuclei_3.8.0_linux_amd64.zip
unzip nuclei.zip nuclei && sudo mv nuclei /usr/local/bin/
git clone https://github.com/projectdiscovery/nuclei-templates.git ~/nuclei-templates-git
git -C ~/nuclei-templates-git checkout 9e97c753      # revisión del 21/10/2026
export NUCLEI_TEMPLATES=~/nuclei-templates-git
```

- Imágenes Docker (se descargan solas la primera vez): `python:3.11-alpine`, `eclipse-mosquitto:2.0`, `nicolaka/netshoot`;
  para el PLC, `openplc:v3` construida según `plc/README_PLC.md`.

## 3. Experimento principal: matriz de confusión (Tablas 4.3 y 4.4)

```bash
bash reproducir.sh
```

El script ejecuta, en orden: comprobación de requisitos, entorno virtual, pruebas unitarias, creación de la red y de los
41 contenedores, auditoría de los 41 objetivos (unos 6–7 min), matriz de confusión, evaluación por hallazgo y comparación
con la ejecución documentada. La salida queda en `salida_reproduccion/`. Resultado esperado:

```
TP: documentado=25  reproducido=25
FN: documentado=0   reproducido=0
FP: documentado=0   reproducido=0
TN: documentado=16  reproducido=16
escenarios con veredicto distinto: ninguno
```

Comprobado en una copia limpia del repositorio el 11/11/2026: matriz idéntica (25/0/0/16) y evaluación por hallazgo
idéntica (precisión 33/38, cobertura 33/34).

## 4. Medidas complementarias

Ejecutar desde la raíz del repositorio con el banco levantado (sección 3) y el entorno virtual creado. Los scripts que
capturan tráfico usan `tcpdump` dentro de `nicolaka/netshoot` sobre el puente de `vantedge_net`.

| Resultado en la memoria | Orden | Salida |
| --- | --- | --- |
| Tiempo por activo (Tabla 4.5, Fig. 4.4) | `./venv/bin/python scripts/medir_tiempos.py 10 testbed/groundtruth.json` | `tiempos_modulo.json` |
| *Template Clustering* (Tabla 4.6, Fig. 4.5) | `bash scripts/medir_clustering.sh 192.168.100.11 8069 5 resultados_nuevos/clustering` | `resumen.txt`, PCAP |
| Carga sobre el servicio (Tabla 4.8) | `./venv/bin/python scripts/medir_carga.py 192.168.100.20 502 modbus p_modbus_01 br-<id>` (ídem con 102/s7, 1883/mqtt, 8069/http) | `carga_<contenedor>.json` |
| Configuraciones web (Tabla 4.11) | `PYTHON=./venv/bin/python bash scripts/medir_configuraciones_web.sh 192.168.100.11 8069 5 resultados_nuevos/conf` | `resumen.txt`, `filas.csv` |
| Ciclo del PLC (Tabla 4.9, Fig. 4.6) | ver `plc/README_PLC.md`; después `./venv/bin/python scripts/medir_ciclo_plc.py 192.168.100.60 502 plc_run1.json` | JSON por fase |
| Control de sensibilidad del PLC | `./venv/bin/python scripts/control_cpu_plc.py 192.168.100.60 502 plc_openplc control_cpu_1.json` | JSON |
| Evaluación por hallazgo (Tabla 4.4) | `./venv/bin/python scripts/evaluar_hallazgos.py matriz.json evaluacion_hallazgos.json` | JSON |

`br-<id>` es la interfaz puente de la red: `echo br-$(docker network inspect vantedge_net -f '{{.Id}}' | cut -c1-12)`.

Comprobación del 11/11/2026 en copia limpia (una repetición de cada medida, solo para verificar que los scripts
funcionan): *clustering* 7,06 % (documentado 7,01 ± 0,69 %, n = 5); configuración web completa 17.303 paquetes
(documentado 17.068 ± 194); verificación L7 propia 46 paquetes (documentado 46); PLC compilado y en marcha a
100 ciclos/s siguiendo `plc/README_PLC.md`. Los tiempos y recuentos de paquetes varían entre máquinas y ejecuciones;
lo reproducible es el orden de magnitud y la matriz de confusión.

## 5. Notas

- `resultados/plc_ciclo/run_plc.sh` es el guion tal como se ejecutó en la máquina de medida (contiene sus rutas
  absolutas); se conserva como registro, no como instrucción.
- La campaña sobre Shodan (`radar.py` sin `--targets`) requiere `SHODAN_API_KEY` y **no** forma parte de la
  reproducción: la memoria no usa sus resultados como evidencia (§4.1.1).
- Apagar el banco: `docker rm -f $(docker ps -aq --filter network=vantedge_net); docker network rm vantedge_net`.
