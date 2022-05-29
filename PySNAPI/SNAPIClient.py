import json
import socket
import ssl
import os
import base64
import hashlib

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
        self._meta_inf = meta_inf
    
    def response_code(self):
        if self._meta_inf == None: return None
        return self._meta_inf["response_code"]

    def meta_inf(self):
        if self._meta_inf == None: return None
        return self._meta_inf
        
    def payload(self):
        if self._payload == None: return None
        return self._payload    

def get_file(fileResponse: SNAPIResponse):
    if fileResponse.response_code() != 200:
        return None
    payload = fileResponse.payload()
    if payload == None: return None
    if "filename" not in payload: return None
    if "data" not in payload: return None
    filename = payload["filename"]
    filebytes = base64.b64decode(payload["data"])
    return filename, filebytes

def write_file(fileResponse: SNAPIResponse, srcPath: str):
    if fileResponse.response_code() != 200:
        return False
    payload = fileResponse.payload()
    if payload == None: return False
    if "filename" not in payload: return False
    if "data" not in payload: return False
    filename = payload["filename"]
    filebytes = base64.b64decode(payload["data"])
    filehash = payload["hash"]
    #Verify the hash matches
    if filehash != hashlib.sha256(filebytes).hexdigest(): return False
    if os.path.exists(srcPath): return False
    with open(srcPath, 'wb') as f:
        f.write(filebytes)
    return True
    
class SNAPIClient:
    def __init__(self, host: str, port: int, sslVerify=True, proxy=None, proxy_host=None, proxy_port=None, proxy_auth=None):
        self.host = host
        self.port = port
        self.sslVerify=sslVerify
        self.proxy_auth = proxy_auth
        self.set_proxy(proxy, proxy_host, proxy_port)

    def set_proxy(self, proxy: str, proxy_host: str, proxy_port: int):
        self.proxy = proxy
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port

    def remove_proxy(self):
        self.proxy = None
        self.proxy_host = None
        self.proxy_port = None

    def post(self, route: str, payload: dict, auth=""):
        meta = { "route": route, "request_type": "POST" }
        if self.proxy != None:
            if self.proxy_auth != None:
                meta["proxy_auth"] = self.proxy_auth
            meta["server"] = self.host
            meta["server_port"] = self.port
        if auth != "":
            meta["auth"] = auth
        packet = encode_packet(payload, meta)
        return self.send_packet(packet)

    def get(self, route: str, payload={}, auth=""):
        meta = { "route": route, "request_type": "GET" }
        if self.proxy != None:
            if self.proxy_auth != None:
                meta["proxy_auth"] = self.proxy_auth
            meta["server"] = self.host
            meta["server_port"] = self.port
        if auth != "":
            meta["auth"] = auth
        packet = encode_packet(payload, meta)
        return self.send_packet(packet)

    def download(self, route: str, fileName: str, dest="", auth=""):
        meta = { "route": route, "request_type": "DOWNLOAD"}
        if self.proxy != None:
            if self.proxy_auth != None:
                meta["proxy_auth"] = self.proxy_auth
            meta["server"] = self.host
            meta["server_port"] = self.port
        if auth != "":
            meta["auth"] = auth
        
        payload = { "filename": fileName }
        packet = encode_packet(payload, meta)
        response = self.send_packet(packet)
        if dest != "":
            if write_file(response, dest) == False:
                raise IOError("Could not write file to dest: " + dest)
        return response
    '''
    def download_legacy(self, route: str, fileName: str, dest: str, auth=""):
        #Make the setup request
        meta = { "route": route, "request_type": "DOWNLOAD_SETUP" }
        if auth != "":
            meta["auth"] = auth
        payload = { "filename": fileName }
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
    '''
    #Returns a response object
    def send_packet(self, packet: bytes):
        context = ssl.create_default_context()
        if self.sslVerify==False:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        hostaddr = self.host
        hostport = self.port
        if self.proxy != None:
            hostaddr = self.proxy_host
            hostport = self.proxy_port
        with socket.create_connection((hostaddr, hostport)) as sock:
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