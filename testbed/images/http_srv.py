import sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
MODE = sys.argv[1] if len(sys.argv)>1 else "plain"
PORT = int(sys.argv[2]) if len(sys.argv)>2 else 8069
VULN = open("/app/manager.html","rb").read() if MODE in ("vuln","slow") else b""
HARD = open("/app/manager.html","rb").read() if MODE=="hardened" else b""
class H(BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def do_GET(self):
        p = self.path.split("?")[0]
        if MODE=="slow" and p=="/web/database/manager":
            time.sleep(4)  # excede el watchdog de 3s -> FN esperado
        if p=="/web/database/manager" and MODE in ("vuln","slow","hardened"):
            body = VULN if MODE in ("vuln","slow") else HARD
            self.send_response(200); self.send_header("Content-Type","text/html")
            self.send_header("Content-Length",str(len(body))); self.end_headers()
            self.wfile.write(body); return
        if p in ("/web/login","/web/database/selector") and MODE in ("vuln","slow","hardened"):
            b=b"<html><head><title>Odoo</title></head><body>Login</body></html>"
            self.send_response(200); self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b); return
        b=b"<html><body>Service OK</body></html>"
        self.send_response(200 if MODE!="plain" or p=="/" else 404)
        self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)
ThreadingHTTPServer(("0.0.0.0",PORT),H).serve_forever()  # multihilo: el servidor monohilo serializaba las conexiones concurrentes de Nuclei
