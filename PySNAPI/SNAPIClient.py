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

class SNAPIProxyConfig:
    def __init__(self, host: str, port: int, proxy_token=None, proxy_username_and_password=None):
        self._host = host
        self._port = port
        self._auth = None

        if proxy_token != None:
            self._auth = {"token": proxy_token}
        elif proxy_username_and_password != None:
            self._auth = proxy_username_and_password

    def host(self): return self._host
    def port(self): return self._port
    def auth(self): return self._auth

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
    filehash = payload["sha256"]
    #Verify the hash matches
    if filehash != hashlib.sha256(filebytes).hexdigest(): return None
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
    filehash = payload["sha256"]
    #Verify the hash matches
    if filehash != hashlib.sha256(filebytes).hexdigest(): return False
    if os.path.exists(srcPath): return False
    with open(srcPath, 'wb') as f:
        f.write(filebytes)
    return True
    
class SNAPIClient:
    def __init__(self, host: str, port: int, sslVerify=True, proxy_config=None):
        self.proxy_config = proxy_config
        self.host = host
        self.port = port
        self.sslVerify=sslVerify

    def set_proxy_config(self, proxy_config: SNAPIProxyConfig):
        self.proxy_config = proxy_config

    def remove_proxy(self):
        self.proxy_config = None

    def post(self, route: str, payload: dict, auth=""):
        meta = { "route": route, "request_type": "POST" }
        if self.proxy_config != None:
            if self.proxy_config.auth() != None:
                meta["proxy_auth"] = self.proxy_config.auth()
            meta["server"] = self.host
            meta["server_port"] = self.port
        if auth != "":
            meta["auth"] = auth
        packet = encode_packet(payload, meta)
        return self.send_packet(packet)

    def get(self, route: str, payload={}, auth=""):
        meta = { "route": route, "request_type": "GET" }
        if self.proxy_config != None:
            if self.proxy_config.auth() != None:
                meta["proxy_auth"] = self.proxy_config.auth()
            meta["server"] = self.host
            meta["server_port"] = self.port
        if auth != "":
            meta["auth"] = auth
        packet = encode_packet(payload, meta)
        return self.send_packet(packet)

    def download(self, route: str, fileName: str, dest="", auth=""):
        meta = { "route": route, "request_type": "DOWNLOAD"}
        if self.proxy_config != None:
            if self.proxy_config.auth() != None:
                meta["proxy_auth"] = self.proxy_config.auth()
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

    #Returns a response object
    def send_packet(self, packet: bytes):
        context = ssl.create_default_context()
        if self.sslVerify==False:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        hostaddr = self.host
        hostport = self.port
        if self.proxy_config != None:
            hostaddr = self.proxy_config.host()
            hostport = self.proxy_config.port()
        with socket.create_connection((hostaddr, hostport)) as sock:
            with context.wrap_socket(sock, server_hostname=hostaddr) as sslSocket:
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