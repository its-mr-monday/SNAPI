import threading
import socket
import ssl
from ssl import SSLSocket
import json
import datetime
import time
import os
import base64
import hashlib

def encode_packet(payload: dict, meta_inf: int):
    payload_str = json.dumps(payload)
    meta_inf_str = json.dumps({ "response_code": meta_inf})
    packet = f"<snapi_res><meta>{meta_inf_str}</meta><payload>{payload_str}</payload></snapi_res>"
    return packet.encode("utf-8")

def decode_packet(packet: str):
    #decode the packet based on the encode packet function
    meta_inf = None
    payload = None
    def find_between( s, first, last ):
        try:
            start = s.index( first ) + len( first )
            end = s.index( last, start )
            return s[start:end]
        except ValueError as e:
            print(e)
            return ""
    
    meta_str = find_between(packet, "<meta>", "</meta>")
    payload_str = find_between(packet, "<payload>", "</payload>")
    if meta_str != "":
        meta_inf = json.loads(meta_str)
    if payload_str != "":
        payload = json.loads(payload_str)
    return meta_inf, payload

class SNAPIServer:
    def __init__(self, pem_file: str, private_key: str, max_threads=50):
        self.port = 5001
        self.route_map = {}
        self.active_threads = []
        self.max_threads = max_threads
        self.sslContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.sslContext.load_cert_chain(pem_file, private_key)
        self.socket = None
        self.running=False
        self.cleanupThread = None

    def serve(self, host="0.0.0.0", port=5001):
        print("Starting SNAPI (Secure Network Application Interface) Server on port: " + str(port))
        self.running = True
        #Setup the thread cleanup thread
        self.cleanupThread = threading.Thread(target=self.cleanupThreads, daemon=True)
        self.cleanupThread.start()
        #Setup the socket
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        self.socket.bind((host, self.port))
        self.socket.listen(self.max_threads)
        with self.sslContext.wrap_socket(self.socket, server_side=True) as sslSocket:
            while self.running:
                #Handle the connection
                conn, addr = sslSocket.accept()
                if (len(self.active_threads) >= self.max_threads):
                    meta_inf = { "response_code": "503" }
                    payload = { "message": "Server is busy" }
                    conn.sendall(encode_packet(payload, meta_inf))
                    conn.close()
                else:
                    reqThread = threading.Thread(target=self.request_thread, args=(conn, addr), daemon=True)
                    reqThread.start()
                    self.active_threads.append(reqThread)

    def request_thread(self, conn: SSLSocket, addr):
        data = None
        while True:
            try:
                new_data = conn.recv(1024)
                if len(new_data) == 0:
                    break
                if data == None:
                    data = new_data
                else:
                    data += new_data
                if "<snapi_req>" in data.decode("utf-8") and "</snapi_req>" in data.decode("utf-8"):
                    break
            except Exception as e:
                print(e)
                break
        if data != None:
            packet = data.decode("utf-8")
            meta_inf, payload = decode_packet(packet)
            if meta_inf is None or payload is None:
                meta_inf = { "response_code": 400 }
                payload = { "message": "Bad Request" }
                self.log_error(f"{addr} {meta_inf['response_code']} {payload['message']}")
            elif "route" not in meta_inf:
                meta_inf = { "response_code": 400 }
                payload = { "message": "Bad Request" }
                self.log_error(f"{addr} sent a packet without a route")
            elif "request_type" not in meta_inf:
                meta_inf = { "response_code": 400 }
                payload = { "message": "Bad Request" }
                self.log_error(f"{addr} sent a packet without a request_type")
            else:
                route = meta_inf["route"]
                req_type = meta_inf["request_type"]
                
                response = self.process_request(route, payload, meta_inf, addr, req_type)
                meta_inf = response[0]
                payload = response[1]
            encoded_packet = encode_packet(payload, meta_inf)
            conn.sendall(encoded_packet)
        conn.close()
        return

    def process_request(self, route: str, request_payload: dict, request_meta_inf: dict, addr, request_type: str):
        response = None
        if route in self.route_map:
            request_info = { "meta_inf": request_meta_inf, "payload": request_payload }
            response = self.route_map[route](request_type, request_info)
            if response is None:
                response = 400, { "message": "Bad Request" }
            # check if response[0] is a integer and response[1] is a dict
            if isinstance(response[0], int) and isinstance(response[1], dict):
                self.log_request(route, response[0], addr, datetime.datetime.now(), request_type)
                return response
            else:
                response = 400, { "message": "Bad Request" }
        else:
            response = 404, { "message": "404 Route Not Found"}
        self.log_request(route, response[0], addr, datetime.datetime.now(), request_type)
        return response



    def add_route(self, route: str, handler):
        if route in self.route_map:
            print(f"Route {route} already exists")
            return
        self.route_map[route] = handler

    def add_download(self, route: str, srcDir: str, authMethod=None):
        #Check if the route is already in the route map
        if route in self.route_map:
            print(f"Route {route} already exists")
            return
        
        #Check if srcDir exists
        if not os.path.exists(srcDir):
            print(f"{srcDir} does not exist")
            return
        
        self.route_map[route] = lambda req_type, req_info, conn: self.download_handler(req_type, req_info. srcDir, authMethod=authMethod)

    def download_handler(self, request_type: str, request_data: dict, srcDir: str, authMethod):
        current_dir = srcDir
        if request_type != "DOWNLOAD_SETUP" or request_type != "DOWNLOAD_PART":
            return 400, { "message": "Bad Request" }
        payload = request_data["payload"]
        meta_inf = request_data["meta_inf"]
        if authMethod != None:
            auth = meta_inf["auth"]
            if authMethod(auth) == False:
                return 401, { "message": "Unauthorized" }
        if "filename" not in payload:
            return 400, { "message": "Bad Request" }

        srcfile = os.path.join(current_dir, payload["filename"])
        if not os.path.isfile(srcfile):
            return 404, { "message": "File not found" }
        
        filebytes = bytearray()
        with open(srcfile, 'rb') as f:
            filebytes = f.read()
        b64FileString = base64.b64encode(filebytes).decode("utf-8")
        buffer = 8096
        parts = int(len(b64FileString)/buffer)
        fsize = len(b64FileString)
        if len(b64FileString) % buffer != 0:
            parts += 1

        if request_type == "DOWNLOAD_SETUP":
            #Setup the file for upload
            if payload["filename"] != "test.txt":
                return 401, { "message": "Unauthorized" }
            sha = hashlib.sha256(filebytes).hexdigest()
            return 200, { "message": "File has been moved to queue!","filesize": fsize, "parts": parts, "sha": sha, "buffer": 8096, "status": "proceed" }

        elif request_type == "DOWNLOAD_PART":
            #Get the file part
            if "part" not in payload:
                return 400, { "message": "Bad Request" }
            if payload["part"] < 1 or payload["part"] > parts:
                return 400, { "message": "Bad Request" }
            part = payload["part"]
            if part == parts:
                return 200, { "size": 8096, "part": part, "encoding": "base64", "status": "finished", "data": b64FileString[(part-1)*buffer:] }
            else:
                return 200, {"status": "proceed", "size": 8096, "part": part, "encoding": "base64", "data": b64FileString[(part-1)*buffer:part*buffer]}

        else:
            return 400, { "message": "Bad Request" }
        
    def log_request(self, route, response_code, ipaddr, time, req_type):
        print(f"[{time}] {ipaddr[0]} {response_code} {req_type} {route}")

    def log_error(self, errorMessage):
        print(f"[{datetime.datetime.now()}] {errorMessage}")

    def cleanupThreads(self):
        while self.running == True:
            for thread in self.active_threads:
                if thread.is_alive():
                    pass
                self.active_threads.remove(thread)

            time.sleep(5)   #Sleep every 5 seconds