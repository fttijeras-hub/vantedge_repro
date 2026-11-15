#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Vantedge Risk Engine - CLI Orchestrator Wrapper
Punto de entrada ejecutable para campañas de auditoría perimetral orientada a minimizar el impacto.

Modos:
  * Campaña completa (Shodan):   SHODAN_API_KEY=... python radar.py
  * Demostración reproducible:   python radar.py --targets objetivos.json
    (sin Shodan: audita una lista cerrada de objetivos, p. ej. el banco de pruebas Docker)
Todos los parámetros de ritmo y de seguridad operativa se PASAN al motor (ver CONFIG_POR_DEFECTO).
"""

import os
import sys
import json
import argparse
import logging
from modulos_software_tfg import (CONFIG_POR_DEFECTO, ejecutar_pipeline_auditoria_robusto,
                                  ejecutar_pipeline_desde_objetivos)


def parse_args():
    p = argparse.ArgumentParser(description="Vantedge Risk Engine: Orquestador Perimetral de Auditoría IT/OT")
    p.add_argument("--output-dir", type=str, default="./expedientes_tecnicos",
                   help="Ruta de almacenamiento de los dictámenes técnicos compilados.")
    p.add_argument("--rate-limit", type=float, default=CONFIG_POR_DEFECTO["rate_limit_s"],
                   help="Pausa entre activos consecutivos (segundos).")
    p.add_argument("--max-host-errors", type=int, default=CONFIG_POR_DEFECTO["max_host_errors"],
                   help="Fallos consecutivos por host antes del disyuntor de nuclei (-mhe).")
    p.add_argument("--socket-timeout", type=int, default=CONFIG_POR_DEFECTO["socket_timeout_s"],
                   help="Temporizador de guarda de socket (nuclei -timeout y pre-validación TCP).")
    p.add_argument("--max-campaign-failures", type=int, default=CONFIG_POR_DEFECTO["max_fallos_campana"],
                   help="Activos consecutivos sin respuesta tras los cuales se interrumpe la campaña.")
    p.add_argument("--cache-ttl-days", type=float, default=CONFIG_POR_DEFECTO["cache_ttl_dias"],
                   help="Caducidad (días) de una entrada del historial; 0 = no caduca.")
    p.add_argument("--nuclei-templates", type=str, default=CONFIG_POR_DEFECTO["nuclei_templates"],
                   help="Directorio de plantillas de Nuclei (por defecto, el de la instalación).")
    p.add_argument("--http-template-path", action="append", default=[],
                   help="Restringe la pasada HTTP a una ruta de plantillas (repetible).")
    p.add_argument("--targets", type=str, default="",
                   help="JSON con [{'ip':..,'port':..,'entidad':..}]; si se indica no se consulta Shodan.")
    return p.parse_args()


def main():
    args = parse_args()
    cfg = {
        "rate_limit_s": args.rate_limit, "max_host_errors": args.max_host_errors,
        "socket_timeout_s": args.socket_timeout, "max_fallos_campana": args.max_campaign_failures,
        "cache_ttl_dias": args.cache_ttl_days, "nuclei_templates": args.nuclei_templates,
        "http_template_paths": args.http_template_path,
    }
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
                        handlers=[logging.StreamHandler(sys.stdout),
                                  logging.FileHandler("vantedge_execution.log", encoding="utf-8")])
    logging.info("Iniciando Vantedge Risk Engine...")
    logging.info("Configuración: pacing=%.2fs | timeout=%ds | max_host_errors=%d | caducidad_cache=%sd",
                 cfg["rate_limit_s"], cfg["socket_timeout_s"], cfg["max_host_errors"], cfg["cache_ttl_dias"])
    try:
        if args.targets:
            with open(args.targets, encoding="utf-8") as f:
                objetivos = [(o["ip"], int(o["port"]), o.get("entidad", "Objetivo_Controlado")) for o in json.load(f)]
            res = ejecutar_pipeline_desde_objetivos(objetivos, args.output_dir, cfg)
            logging.info("Modo objetivos: %d activos auditados.", len(res))
        else:
            api_key = os.getenv("SHODAN_API_KEY")
            if not api_key:
                sys.stderr.write("[ERROR CRÍTICO CWE-798] Falta la variable de entorno SHODAN_API_KEY.\n")
                sys.exit(1)
            ejecutar_pipeline_auditoria_robusto(api_key=api_key, salida_directorio=args.output_dir, cfg=cfg)
        logging.info("Campaña completada.")
    except KeyboardInterrupt:
        logging.warning("Interrupción por teclado. Abortando de forma limpia...")
        sys.exit(0)
    except Exception as e:
        logging.critical("Fallo en el pipeline de ejecución: %s", str(e))
        sys.exit(2)


if __name__ == "__main__":
    main()
