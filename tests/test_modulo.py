"""Pruebas unitarias del motor (no requieren red ni Docker). Ejecutar: python -m unittest -v tests/test_modulo.py"""
import os, sys, tempfile, time, unittest
from unittest import mock
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import modulos_software_tfg as m


class TestCache(unittest.TestCase):
    def test_entrada_vigente_y_caducada(self):
        ahora = 1_000_000_000.0
        h = {"1.1.1.1": {"ts": ahora - 5*86400, "huella": ""}, "2.2.2.2": {"ts": ahora - 40*86400, "huella": ""},
             "3.3.3.3": ahora - 1*86400}                      # formato antiguo (float)
        self.assertTrue(m.entrada_vigente("1.1.1.1", h, 30, ahora))
        self.assertFalse(m.entrada_vigente("2.2.2.2", h, 30, ahora))   # caducada => se vuelve a auditar
        self.assertTrue(m.entrada_vigente("3.3.3.3", h, 30, ahora))
        self.assertFalse(m.entrada_vigente("9.9.9.9", h, 30, ahora))   # no existe
        self.assertTrue(m.entrada_vigente("2.2.2.2", h, 0, ahora))     # ttl=0 => no caduca

    def test_huella_registrada(self):
        with tempfile.TemporaryDirectory() as d:
            m.HISTORIAL_ESTADO_PATH = os.path.join(d, "c.json")
            h = {}
            m.registrar_activo_auditado("4.4.4.4", h, "modbus-detect")
            self.assertEqual(m.cargar_historial_escaneos()["4.4.4.4"]["huella"], "modbus-detect")


class TestParametros(unittest.TestCase):
    def test_cfg_llega_a_nuclei(self):
        cfg = {**m.CONFIG_POR_DEFECTO, "socket_timeout_s": 7, "max_host_errors": 9,
               "nuclei_bin": "nuclei", "nuclei_templates": "/t"}
        capt = {}
        def falso(cmd, a, c):
            capt["cmd"] = cmd; return [], 0.0, "ok"
        with mock.patch.object(m, "_ejecutar_nuclei", falso):
            m.ejecutar_pasada_http("10.0.0.1", 8069, cfg)
        c = capt["cmd"]
        self.assertEqual(c[c.index("-timeout")+1], "7")
        self.assertEqual(c[c.index("-mhe")+1], "9")
        self.assertIn("-ni", c)          # no se contactan servidores OAST/interactsh de terceros

    def test_sin_shell_ni_interpolacion(self):
        # una IP maliciosa viaja como UN solo argumento; nunca se interpreta por un shell
        cfg = {**m.CONFIG_POR_DEFECTO, "nuclei_bin": "nuclei"}
        capt = {}
        def falso(cmd, a, c):
            capt["cmd"] = cmd; return [], 0.0, "ok"
        with mock.patch.object(m, "_ejecutar_nuclei", falso):
            m.ejecutar_pasada_http("1.2.3.4; rm -rf /", 80, cfg)
        self.assertIsInstance(capt["cmd"], list)
        self.assertIn("1.2.3.4; rm -rf /:80", capt["cmd"])


class TestPacingYDisyuntor(unittest.TestCase):
    def _reg(self, sin=False):
        return {"hallazgos": [], "sin_respuesta": sin, "detectado": False}

    def test_pausa_entre_activos(self):
        with tempfile.TemporaryDirectory() as d:
            m.HISTORIAL_ESTADO_PATH = os.path.join(d, "c.json")
            cfg = {"rate_limit_s": 3.0, "log_jsonl": os.path.join(d, "l.jsonl")}
            obj = [(f"10.0.0.{i}", 80, "x") for i in range(1, 5)]
            with mock.patch.object(m, "auditar_activo", lambda *a, **k: self._reg()), \
                 mock.patch.object(m.time, "sleep") as sl:
                m.ejecutar_pipeline_desde_objetivos(obj, d, cfg)
            self.assertEqual([c.args[0] for c in sl.call_args_list], [3.0]*4)   # una pausa por activo

    def test_disyuntor_de_campana(self):
        with tempfile.TemporaryDirectory() as d:
            m.HISTORIAL_ESTADO_PATH = os.path.join(d, "c.json")
            cfg = {"rate_limit_s": 0, "max_fallos_campana": 3, "log_jsonl": os.path.join(d, "l.jsonl")}
            obj = [(f"10.0.0.{i}", 80, "x") for i in range(1, 10)]
            llamadas = []
            def f(ip, *a, **k):
                llamadas.append(ip); return self._reg(sin=True)
            with mock.patch.object(m, "auditar_activo", f), mock.patch.object(m.time, "sleep"):
                m.ejecutar_pipeline_desde_objetivos(obj, d, cfg)
            self.assertEqual(len(llamadas), 3)       # se interrumpe tras 3 activos consecutivos sin respuesta

    def test_cache_omite_activo_vigente(self):
        with tempfile.TemporaryDirectory() as d:
            m.HISTORIAL_ESTADO_PATH = os.path.join(d, "c.json")
            cfg = {"rate_limit_s": 0, "log_jsonl": os.path.join(d, "l.jsonl")}
            h = {}; m.registrar_activo_auditado("10.0.0.1", h, "")
            llamadas = []
            def f(ip, *a, **k):
                llamadas.append(ip); return self._reg()
            with mock.patch.object(m, "auditar_activo", f), mock.patch.object(m.time, "sleep"):
                m.ejecutar_pipeline_desde_objetivos([("10.0.0.1", 80, "x"), ("10.0.0.2", 80, "y")], d, cfg)
            self.assertEqual(llamadas, ["10.0.0.2"])


class TestFiltroProveedores(unittest.TestCase):
    def test_limitacion_conocida(self):
        # Limitación documentada: una empresa industrial alojada en un proveedor cloud SE DESCARTA.
        self.assertTrue(m.es_infraestructura_proveedor("ACME Industrial en AMAZON Web Services"))
        self.assertFalse(m.es_infraestructura_proveedor("Aguas del Sur S.L."))
        # Limitación documentada: coincidencia por subcadena => falso descarte ("DIGI" en "DIGITAL")
        self.assertTrue(m.es_infraestructura_proveedor("Digitalización Industrial del Sur S.L."))


if __name__ == "__main__":
    unittest.main(verbosity=2)
