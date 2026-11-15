import socket, sys, threading
PROTO = sys.argv[1] if len(sys.argv) > 1 else "modbus"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else (502 if PROTO=="modbus" else 102)

def handle_modbus(c):
    # Lee una peticion Modbus TCP y responde a Read Holding Registers (0x03)
    data = c.recv(1024)
    if len(data) >= 12:
        tid = data[0:2]
        unit = data[6:7]
        func = data[7]
        if func == 0x03:
            qty = int.from_bytes(data[10:12], "big") or 1
            bc = 2*qty
            pdu = bytes([0x03, bc]) + b"\x00"*bc
            resp = tid + b"\x00\x00" + (len(pdu)+1).to_bytes(2,"big") + unit + pdu
            c.sendall(resp)
    c.close()

def handle_s7(c):
    # COTP Connection Request -> Connection Confirm
    req1 = c.recv(1024)
    if not req1: return c.close()
    cc = bytes.fromhex("0300001611d0000100000014")  # COTP CC (longitud TPKT 0x16)
    c.sendall(cc)
    # S7 setup communication -> ack
    req2 = c.recv(1024)
    setup_ack = bytes.fromhex("0300001b02f080320300000000000800000000f0000001000101e0")
    c.sendall(setup_ack)
    # SZL read -> respuesta con cabecera 02f08032070000 y el MLFB 6ES7...
    req3 = c.recv(1024)
    mlfb = b"6ES7 315-2EH14-0AB0 "
    body = bytes.fromhex("02f0803207000000000104ff09003400111c03") + mlfb + b"\x00"*8
    szl = bytes.fromhex("0300") + (len(body)+4).to_bytes(2,"big") + body
    c.sendall(szl)
    c.close()

def serve():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", PORT)); s.listen(50)
    print(f"{PROTO} responder on {PORT}", flush=True)
    while True:
        c,_ = s.accept()
        h = handle_modbus if PROTO=="modbus" else handle_s7
        threading.Thread(target=h, args=(c,), daemon=True).start()
serve()
