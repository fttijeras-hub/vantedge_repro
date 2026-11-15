import json, subprocess, sys
NET="vantedge_net"
def run(c): subprocess.run(c, shell=True, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
# (id, ip, kind, port, vulnerable, descripcion verdad de referencia)
S=[]
# --- VULNERABLES (25) ---
for i,ip in enumerate(range(11,19)):   S.append((f"P-ODOO-{i+1:02d}",f"192.168.100.{ip}","odoo_vuln",8069,True,"Odoo manager sin master_pwd (gestor BD expuesto)"))
S.append(("P-ODOO-SLOW","192.168.100.19","odoo_slow",8069,True,"Odoo vulnerable pero responde >3s (watchdog) -> FN esperado"))
for i,ip in enumerate(range(20,26)):   S.append((f"P-MODBUS-{i+1:02d}",f"192.168.100.{ip}","modbus",502,True,"Modbus TCP 502 abierto, responde Read Holding Registers"))
for i,ip in enumerate(range(30,35)):   S.append((f"P-MQTT-{i+1:02d}",f"192.168.100.{ip}","mqtt_anon",1883,True,"Broker MQTT anonimo (allow_anonymous true)"))
for i,ip in enumerate(range(40,45)):   S.append((f"P-S7-{i+1:02d}",f"192.168.100.{ip}","s7",102,True,"Siemens S7comm 102 abierto, SZL responde 6ES7"))
# --- ENDURECIDOS (16) ---
for i,ip in enumerate(range(111,115)): S.append((f"N-ODOO-{i+1:02d}",f"192.168.100.{ip}","odoo_hard",8069,False,"Odoo manager protegido (sin warning)"))
for i,ip in enumerate(range(120,123)): S.append((f"N-MQTT-{i+1:02d}",f"192.168.100.{ip}","mqtt_auth",1883,False,"Broker MQTT con auth (allow_anonymous false)"))
for i,ip in enumerate(range(130,134)): S.append((f"N-HTTP-{i+1:02d}",f"192.168.100.{ip}","plain",80,False,"Servicio HTTP normal sin exposiciones"))
for i,ip in enumerate(range(140,143)): S.append((f"N-MBCLOSED-{i+1:02d}",f"192.168.100.{ip}","closed",502,False,"Puerto 502 abierto pero NO habla Modbus (pasarela endurecida)"))
for i,ip in enumerate(range(150,152)): S.append((f"N-S7CLOSED-{i+1:02d}",f"192.168.100.{ip}","closed",102,False,"Puerto 102 abierto pero NO habla S7"))

PY_IMG="python:3.11-alpine"; MQ_IMG="eclipse-mosquitto:2.0"
import os
base=os.path.dirname(os.path.abspath(__file__))
def launch(s):
    sid,ip,kind,port,vuln,_=s
    name=sid.lower().replace("-","_")
    run(f"docker rm -f {name}")
    if kind in ("odoo_vuln","odoo_slow","odoo_hard","plain","closed"):
        mode={"odoo_vuln":"vuln","odoo_slow":"slow","odoo_hard":"hardened","plain":"plain","closed":"plain"}[kind]
        html="odoo_manager_vuln.html" if kind in("odoo_vuln","odoo_slow") else ("odoo_manager_hardened.html" if kind=="odoo_hard" else "odoo_manager_vuln.html")
        run(f"docker run -d --name {name} --network {NET} --ip {ip} "
            f"-v {base}/images/http_srv.py:/app/s.py -v {base}/assets/{html}:/app/manager.html "
            f"{PY_IMG} python /app/s.py {mode} {port}")
    elif kind=="modbus":
        run(f"docker run -d --name {name} --network {NET} --ip {ip} -v {base}/images/ot_responder.py:/app/r.py {PY_IMG} python /app/r.py modbus 502")
    elif kind=="s7":
        run(f"docker run -d --name {name} --network {NET} --ip {ip} -v {base}/images/ot_responder.py:/app/r.py {PY_IMG} python /app/r.py s7 102")
    elif kind=="mqtt_anon":
        run(f"docker run -d --name {name} --network {NET} --ip {ip} -v {base}/assets/mosq_anon.conf:/mosquitto/config/mosquitto.conf {MQ_IMG}")
    elif kind=="mqtt_auth":
        run(f"docker run -d --name {name} --network {NET} --ip {ip} -v {base}/assets/mosq_auth.conf:/mosquitto/config/mosquitto.conf -v {base}/assets/mosq_pwd:/mosquitto/config/pwd {MQ_IMG}")

if __name__=="__main__":
    for s in S: launch(s)
    gt=[{"id":s[0],"ip":s[1],"kind":s[2],"port":s[3],"vulnerable":s[4],"ground_truth":s[5]} for s in S]
    json.dump(gt, open(f"{base}/groundtruth.json","w"), indent=2, ensure_ascii=False)
    pos=sum(1 for s in S if s[4]); print(f"Lanzados {len(S)} escenarios: {pos} vulnerables + {len(S)-pos} endurecidos")
