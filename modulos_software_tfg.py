"""
UNIVERSIDAD DE GRANADA - FACULTAD DE CIENCIAS / ETSIIT
Grado en Ingeniería Electrónica Industrial
Proyecto: Vantedge Risk Engine - Auditoría Perimetral y Ciberseguridad en Redes Industriales (OT/IIoT)

MÓDULOS CONSOLIDADOS DE INGENIERÍA DE SOFTWARE
- Módulo 1: Orquestador Principal, Tolerancia a Fallos y Gestión de Estado (Core Engine)
- Módulo 2: Inspección de Capa de Aplicación L7 y Parsing Estructurado del DOM
- Módulo 3: Algoritmo Heurístico de Filtrado de Red y Descarte de ISPs
- Módulo 4: Evaluación de Criticidad y Matriz de Riesgo de Infraestructuras
- Módulo 5: Compilación Automatizada de Expedientes Técnicos de Auditoría
"""

import os
import socket
import subprocess
import sys
import json
import time
import re
import pathlib
import requests
from bs4 import BeautifulSoup
import shodan
import markdown

# =============================================================================
# MÓDULO 1: ORQUESTADOR PRINCIPAL, TOLERANCIA A FALLOS Y GESTIÓN DE ESTADO
# =============================================================================
# Diseño: ejecución SECUENCIAL (un activo cada vez). No hay hilos ni asincronía:
# la limitación de carga sobre el objetivo es una decisión de diseño, no una carencia.

HISTORIAL_ESTADO_PATH = "telemetry_cache.json"
PUERTOS_OT = (502, 102, 1883)          # Modbus TCP, Siemens S7comm, MQTT
PLATAFORMA_WINDOWS = os.name == "nt"

# Parámetros de seguridad operativa. Son los ÚNICOS puntos donde se fija el ritmo y
# los límites de la campaña; radar.py los sobrescribe desde la línea de comandos.
CONFIG_POR_DEFECTO = {
    "rate_limit_s": 3.0,        # pausa entre activos consecutivos (pacing)
    "api_pause_s": 2.0,         # pausa entre consultas a la API de Shodan
    "socket_timeout_s": 3,      # nuclei -timeout
    "max_host_errors": 3,       # nuclei -mhe (disyuntor por host)
    "max_fallos_campana": 5,    # activos consecutivos sin respuesta => se interrumpe la campaña
    "cache_ttl_dias": 30,       # caducidad de una entrada del historial (0 = no caduca)
    "nuclei_bin": os.environ.get("NUCLEI_BIN", "nuclei.exe" if PLATAFORMA_WINDOWS else "nuclei"),
    "nuclei_templates": os.environ.get("NUCLEI_TEMPLATES", ""),   # "" = directorio por defecto de nuclei
    "http_template_paths": [],  # si se indica, restringe la pasada HTTP a estas rutas (-t)
    "timeout_proceso_s": 600,   # tope duro de cada llamada a nuclei
    "log_jsonl": "auditoria_log.jsonl",
}


def cargar_historial_escaneos() -> dict:
    """Carga en memoria el registro de activos auditados (búsqueda O(1) por IP)."""
    if os.path.exists(HISTORIAL_ESTADO_PATH):
        try:
            with open(HISTORIAL_ESTADO_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}
    return {}


def registrar_activo_auditado(ip: str, historial: dict, huella: str = ""):
    """Persiste la marca temporal del ensayo y una huella del estado observado.
    La huella (hash de lo detectado) permite saber si el activo ha cambiado entre auditorías."""
    historial[ip] = {"ts": time.time(), "huella": huella}
    with open(HISTORIAL_ESTADO_PATH, "w", encoding="utf-8") as f:
        json.dump(historial, f, indent=2)


def entrada_vigente(ip: str, historial: dict, ttl_dias: float, ahora: float = None) -> bool:
    """True si la IP figura en el historial Y su entrada no ha caducado.
    Compatible con el formato antiguo (valor = float con el timestamp)."""
    if ip not in historial:
        return False
    if not ttl_dias:
        return True
    ahora = time.time() if ahora is None else ahora
    v = historial[ip]
    ts = v["ts"] if isinstance(v, dict) else float(v)
    return (ahora - ts) < ttl_dias * 86400


def resolver_identidad_x509_pasiva(shodan_match: dict) -> str:
    """
    Extrae la entidad corporativa a partir del campo 'Organization' (O) del certificado X.509
    que Shodan indexó durante el handshake TLS. LIMITACIÓN: el campo O lo declara quien emite el
    certificado; es un indicio de titularidad, no una prueba (puede estar vacío, ser genérico o
    pertenecer a un tercero, p. ej. un proveedor de alojamiento).
    """
    if 'ssl' in shodan_match and 'cert' in shodan_match['ssl']:
        subject = shodan_match['ssl']['cert'].get('subject', {})
        org = subject.get('O')
        if org and org != "Desconocida":
            return org
    return shodan_match.get('org', "Entidad_No_Identificada")


PLANTILLAS_OT = [
    "network/detection/modbus-detect.yaml",
    "network/detection/ics/siemens/siemens-s7-detect.yaml",
    "javascript/misconfiguration/mqtt-uauth-broker.yaml",
]


def _ruta_plantilla(cfg: dict, relativa: str) -> str:
    base = cfg.get("nuclei_templates") or os.path.join(os.path.expanduser("~"), "nuclei-templates")
    return os.path.join(base, relativa)


def _log_jsonl(cfg: dict, registro: dict):
    """Traza append-only de cada decisión del motor (evidencia de auditoría)."""
    with open(cfg["log_jsonl"], "a", encoding="utf-8") as f:
        f.write(json.dumps(registro, ensure_ascii=False) + "\n")


def _ejecutar_nuclei(comando: list, archivo_salida: str, cfg: dict):
    """Lanza nuclei SIN shell (lista de argumentos => no hay interpolación de comandos, CWE-78).
    Devuelve (hallazgos_ids, segundos, estado) con estado in {'ok','timeout','error'}."""
    t0 = time.time()
    estado = "ok"
    try:
        subprocess.run(comando, shell=False, timeout=cfg["timeout_proceso_s"],
                       stdin=subprocess.DEVNULL,   # nuclei lee objetivos de stdin si está abierto
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        estado = "timeout"
    except OSError:
        estado = "error"
    dt = time.time() - t0
    ids = []
    if os.path.exists(archivo_salida):
        with open(archivo_salida, "r", encoding="utf-8", errors="ignore") as f:
            for linea in f:
                try:
                    ids.append(json.loads(linea).get("template-id", "?"))
                except json.JSONDecodeError:
                    pass
        try:
            os.remove(archivo_salida)
        except OSError:
            pass
    return ids, dt, estado


def puerto_abierto(ip: str, port: int, timeout: float) -> bool:
    """Pre-validación TCP (connect). Evita lanzar el escaneo contra puertos cerrados o sin respuesta
    y alimenta el disyuntor de campaña."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def ejecutar_pasada_ot(ip: str, port: int, cfg: dict) -> dict:
    """Pasada de detección de buses industriales (Modbus, S7comm, MQTT).
    Solo ejecuta plantillas de DETECCIÓN (lectura de identificación / handshake); no emite
    escrituras ni órdenes de control."""
    if port not in PUERTOS_OT:
        return {"ids": [], "t": 0.0, "estado": "omitida"}
    archivo = f"ot_{ip}_{port}.jsonl"
    comando = [cfg["nuclei_bin"], "-u", f"{ip}:{port}", "-timeout", str(cfg["socket_timeout_s"]),
               "-ni", "-duc", "-jsonl", "-o", archivo, "-silent"]
    for plantilla in PLANTILLAS_OT:
        comando += ["-t", _ruta_plantilla(cfg, plantilla)]
    ids, dt, estado = _ejecutar_nuclei(comando, archivo, cfg)
    return {"ids": ids, "t": dt, "estado": estado}


def ejecutar_pasada_http(ip: str, port: int, cfg: dict) -> dict:
    """Pasada HTTP con los indicadores del motor: tags panel/exposure/misconfig, severidad alta."""
    archivo = f"http_{ip}_{port}.jsonl"
    comando = [cfg["nuclei_bin"], "-u", f"{ip}:{port}",
               "-tags", "panel,exposure,misconfig", "-severity", "critical,high",
               "-mhe", str(cfg["max_host_errors"]), "-timeout", str(cfg["socket_timeout_s"]),
               "-ni", "-duc",   # sin servidores OAST/interactsh de terceros ni comprobación de actualizaciones
               "-jsonl", "-o", archivo, "-silent"]
    if cfg.get("http_template_paths"):
        for ruta in cfg["http_template_paths"]:
            comando += ["-t", _ruta_plantilla(cfg, ruta)]
    elif cfg.get("nuclei_templates"):
        comando += ["-t", cfg["nuclei_templates"]]
    ids, dt, estado = _ejecutar_nuclei(comando, archivo, cfg)
    return {"ids": ids, "t": dt, "estado": estado}


def auditar_activo(ip: str, port: int, entidad: str, salida_directorio: str, cfg: dict) -> dict:
    """Auditoría de UN activo. Servicios OT => pasada OT; servicios web => pasada HTTP + inspección L7.
    Devuelve un registro con hallazgos, tiempos y estado (también se vuelca al log JSONL)."""
    t0 = time.time()
    reg = {"ip": ip, "port": port, "entidad": entidad, "inicio": time.strftime("%Y-%m-%dT%H:%M:%S"),
           "hallazgos": [], "pasadas": {}}
    reg["puerto_abierto"] = puerto_abierto(ip, port, cfg["socket_timeout_s"])
    reg["sin_respuesta"] = not reg["puerto_abierto"]
    if reg["puerto_abierto"]:
        if port in PUERTOS_OT:
            r = ejecutar_pasada_ot(ip, port, cfg)
            reg["pasadas"]["ot"] = {"t": round(r["t"], 3), "estado": r["estado"]}
            reg["hallazgos"] += r["ids"]
            vector = "OT-Exposure-Perimetral"
        else:
            r = ejecutar_pasada_http(ip, port, cfg)
            reg["pasadas"]["http"] = {"t": round(r["t"], 3), "estado": r["estado"]}
            reg["hallazgos"] += r["ids"]
            t1 = time.time()
            l7 = verificar_integridad_endpoints_l7(ip, port)
            reg["pasadas"]["l7"] = {"t": round(time.time() - t1, 3), "bases_datos": len(l7["bases_datos"])}
            if l7["elementos_expuestos"]:
                reg["hallazgos"].append("l7-odoo-unprotected")
            vector = "CVE-Misconfig-Perimetral"
    else:
        vector = ""
    reg["hallazgos"] = sorted(set(reg["hallazgos"]))
    reg["detectado"] = bool(reg["hallazgos"])
    if reg["detectado"]:
        generar_expediente_tecnico(ip, port, entidad, vector, salida_directorio)
    reg["t_total_s"] = round(time.time() - t0, 3)
    _log_jsonl(cfg, reg)
    return reg


def ejecutar_pipeline_desde_objetivos(objetivos: list, salida_directorio: str, cfg: dict = None) -> list:
    """Audita una lista cerrada de objetivos [(ip, port, entidad), ...] SIN consultar Shodan.
    Es el modo de demostración reproducible sobre el banco de pruebas controlado.
    Aplica caché con caducidad, pacing entre activos y disyuntor de campaña."""
    cfg = {**CONFIG_POR_DEFECTO, **(cfg or {})}
    historial = cargar_historial_escaneos()
    resultados, fallos_seguidos = [], 0
    for (ip, port, entidad) in objetivos:
        if entrada_vigente(ip, historial, cfg["cache_ttl_dias"]):
            _log_jsonl(cfg, {"ip": ip, "port": port, "omitido": "entrada vigente en historial"})
            continue
        reg = auditar_activo(ip, port, entidad, salida_directorio, cfg)
        resultados.append(reg)
        registrar_activo_auditado(ip, historial, huella="|".join(reg["hallazgos"]))
        fallos_seguidos = fallos_seguidos + 1 if reg["sin_respuesta"] else 0
        if fallos_seguidos >= cfg["max_fallos_campana"]:
            _log_jsonl(cfg, {"campana_interrumpida": True, "motivo": "fallos consecutivos"})
            break
        time.sleep(cfg["rate_limit_s"])   # pacing entre activos consecutivos
    return resultados


def ejecutar_pipeline_auditoria_robusto(api_key: str, salida_directorio: str, cfg: dict = None):
    """
    Pipeline completo: prospección pasiva (Shodan) -> filtrado -> auditoría secuencial.
    Control de tasa, watchdog de socket, disyuntor por host (-mhe) y de campaña, y caché con TTL.
    """
    cfg = {**CONFIG_POR_DEFECTO, **(cfg or {})}
    api = shodan.Shodan(api_key)
    historial = cargar_historial_escaneos()

    vectores = [
        'http.html:"/web/database/manager" country:"ES"',
        'ssl.cert.subject.O:"S.L." country:"ES" port:443',
        'product:"MongoDB" authentication:disabled country:"ES"',
        'port:502 country:"ES"'
    ]
    fallos_seguidos = 0
    for query in vectores:
        try:
            time.sleep(cfg["api_pause_s"])
            results = api.search(query, page=1)
            objetivos = []
            for result in results.get('matches', []):
                ip, port = result['ip_str'], result['port']
                if entrada_vigente(ip, historial, cfg["cache_ttl_dias"]):
                    continue
                entidad = filtrar_y_normalizar_entidad(resolver_identidad_x509_pasiva(result))
                if es_infraestructura_proveedor(entidad):
                    _log_jsonl(cfg, {"ip": ip, "port": port, "descartado": "proveedor de infraestructura",
                                     "entidad": entidad})
                    continue
                objetivos.append((ip, port, entidad))
            for (ip, port, entidad) in objetivos:
                reg = auditar_activo(ip, port, entidad, salida_directorio, cfg)
                registrar_activo_auditado(ip, historial, huella="|".join(reg["hallazgos"]))
                fallos_seguidos = fallos_seguidos + 1 if reg["sin_respuesta"] else 0
                if fallos_seguidos >= cfg["max_fallos_campana"]:
                    _log_jsonl(cfg, {"campana_interrumpida": True, "motivo": "fallos consecutivos"})
                    return
                time.sleep(cfg["rate_limit_s"])
        except shodan.APIError as e:
            sys.stderr.write(f"Excepción controlada en Shodan API: {e}\n")
            time.sleep(5)

# =============================================================================
# MÓDULO 2: INSPECCIÓN L7 Y PARSING ESTRUCTURADO DEL DOM
# =============================================================================

def verificar_integridad_endpoints_l7(ip: str, port: int) -> dict:
    """
    Inspecciona endpoints HTTP/HTTPS a nivel de capa de aplicación para
    verificar la exposición de selectores de bases de datos y formularios no autenticados.
    """
    endpoints = [
        f"http://{ip}:{port}/web/login",
        f"http://{ip}:{port}/web/database/selector",
        f"http://{ip}:{port}/web/database/manager"
    ]
    
    diagnostico = {"titulo": None, "bases_datos": [], "elementos_expuestos": False}
    
    for url in endpoints:
        try:
            r = requests.get(url, timeout=5, allow_redirects=True)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, 'html.parser')
                if soup.title:
                    diagnostico["titulo"] = soup.title.string.strip()
                
                # Extracción de esquemas relacionales expuestos
                inputs = soup.find_all('input', {'name': 'db'})
                for db in inputs:
                    val = db.get('value')
                    if val and val not in diagnostico["bases_datos"]:
                        diagnostico["bases_datos"].append(val)
                
                if "Warning, your Odoo database manager is not protected" in r.text:
                    diagnostico["elementos_expuestos"] = True
        except requests.exceptions.RequestException:
            continue
            
    return diagnostico

# =============================================================================
# MÓDULO 3: FILTRADO HEURÍSTICO Y NORMALIZACIÓN DE RED
# =============================================================================

PROVEEDORES_INFRAESTRUCTURA = [
    "TELEFONICA", "VODAFONE", "ORANGE", "ARSYS", "HOSTING", "AMAZON",
    "GOOGLE", "MICROSOFT", "OVH", "DIGI", "MASMOVIL", "CLOUDFLARE",
    "HETZNER", "ORACLE", "DIGITAL OCEAN"
]

def es_infraestructura_proveedor(nombre: str) -> bool:
    """Evalúa si una entidad corresponde a un ISP, carrier o CPD en lugar de un activo corporativo/industrial."""
    return any(p in nombre.upper() for p in PROVEEDORES_INFRAESTRUCTURA)

def filtrar_y_normalizar_entidad(crudo: str) -> str:
    """Aplica transformaciones de cadenas para extraer la razón social o identificador de infraestructura."""
    if not crudo:
        return "Entidad_No_Identificada"
    ruido = ["Login | ", "Odoo", "| Odoo", " - Inicio", "Welcome to ", "Bienvenido a "]
    for r in ruido:
        crudo = crudo.replace(r, "")
    nombre = re.sub(r"\s+", " ", crudo).strip(" -|:")
    return nombre or "Entidad_No_Identificada"

# =============================================================================
# MÓDULO 4: EVALUACIÓN DE CRITICIDAD Y MATRIZ DE RIESGO
# =============================================================================

PESOS_SECTOR_CRITICO = {
    "infraestructura_critica": 10,
    "logistica_industrial": 9,
    "manufactura_ot": 8,
    "servicios_generales": 6
}

def calcular_indice_criticidad(sector: str, severidad_cvss: float) -> float:
    """Calcula un índice normalizado (0-100) para priorizar el tratamiento del incidente."""
    peso = PESOS_SECTOR_CRITICO.get(sector, 5)
    score_base = peso * 7.0
    if severidad_cvss >= 9.0:
        score_base += 30.0
    elif severidad_cvss >= 7.0:
        score_base += 15.0
    return min(score_base, 100.0)

# =============================================================================
# MÓDULO 5: COMPILACIÓN FORMAL DE EXPEDIENTES TÉCNICOS
# =============================================================================

def compilar_informe_tecnico_html(md_path: pathlib.Path, html_path: pathlib.Path):
    """Convierte el informe técnico Markdown en un documento HTML normalizado según estilos de laboratorio."""
    md_text = md_path.read_text(encoding="utf-8")
    cuerpo = markdown.markdown(md_text, extensions=["tables", "fenced_code", "toc"])
    
    plantilla = f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>Dictamen Técnico de Seguridad Perimetral</title>
  <style>
    body {{ font-family: 'Arial', sans-serif; font-size: 10pt; line-height: 1.5; color: #222; }}
    table {{ width: 100%; border-collapse: collapse; margin: 15px 0; font-size: 9pt; }}
    th, td {{ border: 1px solid #ccc; padding: 6px 10px; text-align: left; }}
    th {{ background-color: #2c3e50; color: #fff; }}
    code {{ font-family: 'Consolas', monospace; background-color: #f4f4f4; padding: 2px 4px; }}
    @media print {{ @page {{ size: A4; margin: 20mm; }} }}
  </style>
</head>
<body>
  <h1>Informe Técnico de Vulnerabilidad Perimetral</h1>
  {cuerpo}
</body>
</html>"""
    html_path.write_text(plantilla, encoding="utf-8")

def generar_expediente_tecnico(ip: str, port: int, entidad: str, template: str, ruta_salida: str):
    """Escribe el reporte estructurado de vulnerabilidad en disco."""
    os.makedirs(ruta_salida, exist_ok=True)
    reporte = (
        f"# Dictamen Técnico: Incidente Perimetral en {ip}:{port}\n\n"
        f"- **Entidad Afectada:** {entidad}\n"
        f"- **Vector Detectado:** {template}\n"
        f"- **Fecha:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
    )
    salida = pathlib.Path(ruta_salida) / f"Reporte_{ip}_{port}.md"
    salida.write_text(reporte, encoding="utf-8")
