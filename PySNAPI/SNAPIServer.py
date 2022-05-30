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

class SNAPIRequest:
    def __init__(self, payload: dict, meta_inf: dict):
        self._payload = payload
        self._meta_inf = meta_inf
    
    def payload(self):
        if self._payload == None: return None
        return self._payload

    def meta_inf(self):
        if self._meta_inf == None: return None
        return self._meta_inf

    def request_type(self):
        if self._meta_inf == None: return None
        return self._meta_inf["request_type"]

    def route(self):
        if self._meta_inf == None: return None
        return self._meta_inf["route"]

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
        try:
            print("Starting PySNAPI (Secure Network Application Interface) Server on port: " + str(port))
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
                        payload = { "message": "Server is busy" }
                        conn.sendall(encode_packet(payload, 503))
                        conn.close()
                    else:
                        reqThread = threading.Thread(target=self.request_thread, args=(conn, addr), daemon=True)
                        reqThread.start()
                        self.active_threads.append(reqThread)
        except KeyboardInterrupt:
            print("\nSNAPI Server shutting down!")
            self.__suspendThreads()

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
                snapi_req = SNAPIRequest(payload, meta_inf)
                route = meta_inf["route"]
                req_type = meta_inf["request_type"]
                
                response = self.process_request(snapi_req, addr)
                meta_inf = response[0]
                payload = response[1]
            encoded_packet = encode_packet(payload, meta_inf)
            conn.sendall(encoded_packet)
        conn.close()
        return

    def process_request(self, request: SNAPIRequest, addr):
        #request_meta_inf = request.meta_inf()
        #equest_payload = request.payload()
        route = request.route()
        request_type = request.request_type()
        response = None
        if route in self.route_map:
            response = self.route_map[route](request)
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
            raise IOError(f"Route {route} already exists")
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
        
        self.route_map[route] = lambda request: self.download_handler(srcDir, request, authMethod=authMethod)

    def download_handler(self, srcDir: str, request: SNAPIRequest, authMethod=None):
        request_type = request.request_type()
        current_dir = srcDir
        if request_type != "DOWNLOAD":
            return 400, { "message": "Bad Request" }
        
        payload = request.payload()
        meta_inf = request.meta_inf()

        if authMethod != None:
            if "auth" not in meta_inf:
                return 401, { "message": "Unauthorized" }
            auth = meta_inf["auth"]
            if authMethod(auth) != True:
                return 401, { "message": "Unauthorized" }

        if "filename" not in payload:
            return 400, { "message": "Bad Request" }
        filename = payload["filename"]
        if filename == "":
            return 400, { "message": "Bad Request" }
        srcpath = os.path.join(current_dir, filename)

        #Prevent file system traversal
        srcpathdir = os.path.dirname(srcpath)
        if srcpathdir != current_dir:
            return 400, { "message": "Bad Request" }
        if not os.path.exists(srcpath):
            return 404, { "message": "File Not Found" }

        filebytes = None
        with open(srcpath, "rb") as f:
            filebytes = f.read()
        
        if filebytes is None:
            return 500, { "message": "Internal Server Error" }
        
        b64FileString = base64.b64encode(filebytes).decode("utf-8")
        fsize = len(b64FileString)
        fhash = hashlib.sha256(filebytes).hexdigest()
        
        return 200, { "data": b64FileString, "filename": filename, "filesize": fsize, "sha256": fhash }

    def log_request(self, route, response_code, ipaddr, time, req_type):
        print(f"[{time}] {ipaddr[0]} {response_code} {req_type} {route}")

    def log_error(self, errorMessage):
        print(f"[{datetime.datetime.now()}] Error: {errorMessage}")

    def cleanupThreads(self):
        while self.running == True:
            for thread in self.active_threads:
                if thread.is_alive():
                    pass
                self.active_threads.remove(thread)

            time.sleep(1)   #Sleep every second

    def __suspendThreads(self):
        self.running = False
        for thread in self.active_threads:
            if thread.is_alive():
                thread.join()
        self.cleanupThread.join()
