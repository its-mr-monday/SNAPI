import json
import socket
import ssl
import os
import base64
import hashlib
import time
def encode_packet(payload: dict, meta_inf: dict):
    payload_str = json.dumps(payload)
    meta_inf_str = json.dumps(meta_inf)
    packet = f"<snapi_req><meta>{meta_inf_str}</meta><payload>{payload_str}</payload></snapi_req>"
    return packet.encode("utf-8")

def decode_packet(packet: str):
    meta_inf = None
    payload = None
    def find_between(s, first, last):
        try:
            start = s.index(first) + len(first)
            end = s.index(last, start)
            return s[start:end]
        except ValueError:
            return ""
    meta_str = find_between(packet, "<meta>", "</meta>")
    payload_str = find_between(packet, "<payload>", "</payload>")
    if meta_str != "":
        meta_inf = json.loads(meta_str)
    if payload_str != "":
        payload = json.loads(payload_str)
    return meta_inf, payload

class SNAPIResponse:
    def __init__(self, payload:dict, meta_inf: dict):
        self._payload = payload
        self.meta_inf = meta_inf
    
    def response_code(self):
        if self.meta_inf == None: return None
        return self.meta_inf["response_code"]

    def payload(self):
        if self._payload == None: return None
        return self._payload    

class SNAPIClient:
    def __init__(self, host: str, port: int, sslVerify=True):
        self.host = host
        self.port = port
        self.sslVerify=sslVerify

    def post(self, route: str, payload: dict, auth=""):
        meta = { "route": route, "request_type": "POST" }
        if auth != "":
            meta["auth"] = auth
        packet = encode_packet(payload, meta)
        return self.send_packet(packet)

    def get(self, route: str, payload={}, auth=""):
        meta = { "route": route, "request_type": "GET" }
        if auth != "":
            meta["auth"] = auth
        packet = encode_packet(payload, meta)
        return self.send_packet(packet)

    def download(self, route: str, fileName: str, auth="", dest=""):
        #Make the setup request
        meta = { "route": route, "request_type": "DOWNLOAD_SETUP" }
        if auth != "":
            meta["auth"] = auth
        payload = { "fileName": fileName }
        packet = encode_packet(payload, meta)
        response = self.send_packet(packet)
        if response.response_code() != 200:
            return False
        #Get the file size
        fileSize = response.payload()["filesize"]
        parts = response.payload()["parts"]
        sha = response.payload()["sha"]
        buffer = response.payload()["buffer"]
        status = response.payload()["status"]
        current_part = 1
        b64FileString = ""
        while status == "proceed":
            #keep fetching the parts
            meta = { "route": route, "request_type": "DOWNLOAD_PART" }
            if auth != "":
                meta["auth"] = auth
            
            payload = { "filename": fileName, "part": current_part}
            packet = encode_packet(payload, meta)
            response = self.send_packet(packet)
            if response.response_code() != 200:
                return False
            b64FileString += response.payload()["data"]
            status = response.payload()["status"]

        if b64FileString == "":
            return False

        if os.path.isfile(dest):
            return False

        if os.path.isdir(dest):
            return False

        fileBytes = base64.b64decode(b64FileString)
        #Verify these bytes
        h = hashlib.new('sha256')
        h.update(fileBytes)
        hash = h.hexdigest()

        if hash != sha:
            return False
        
        with open(dest, 'wb') as f:
            f.write(fileBytes)
        return True

    #Returns a response object
    def send_packet(self, packet: bytes):
        context = ssl.create_default_context()
        if self.sslVerify==False:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((self.host, self.port)) as sock:
            with context.wrap_socket(sock, server_hostname=self.host) as sslSocket:
                print(packet.decode("utf-8"))
                sslSocket.sendall(packet)
                data = None
                while True:
                    try:
                        new_data = sslSocket.recv(1024)
                        if len(new_data) == 0:
                            break
                        if data == None:
                            data = new_data
                        else:
                            data += new_data
                    except Exception as e:
                        print(e)
                        break
                if data != None:
                    print(data.decode('utf-8'))
                    meta_inf, payload = decode_packet(data.decode("utf-8"))
                    if meta_inf is not None or payload is not None:
                        return SNAPIResponse(payload, meta_inf)
        return SNAPIResponse(None, None)