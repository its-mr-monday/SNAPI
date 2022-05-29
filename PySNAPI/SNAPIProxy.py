from PySNAPI.SNAPIClient import SNAPIClient, SNAPIResponse, socket, ssl, json
from PySNAPI.SNAPIServer import encode_packet, decode_packet, threading, time, datetime
from ssl import SSLSocket



class SNAPIProxy:
    def __init__(self, pem_file: str, private_key: str, host="0.0.0.0", port=5002, max_threads=50, sslVerify=True,auth=None, proxy_auth=None, proxy=None, proxy_host=None, proxy_port=None):
        self.host = host
        self.port = port
        self.sslVerify = sslVerify
        self.running = False
        self.max_threads = max_threads
        self.active_threads = []
        self.sslContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.sslContext.load_cert_chain(pem_file, private_key)
        self.socket = None
        self.cleanupThread = None
        self.auth = auth
        self.proxy_auth = proxy_auth
        self.set_proxy(proxy, proxy_host, proxy_port)

    def set_proxy(self, proxy: str, proxy_host: str, proxy_port: int):
        self.proxy = proxy
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port

    def set_auth(self, auth: callable):
        self.auth = auth

    def set_proxy_auth_token(self, token:str):
        self.proxy_auth = { "token": token }

    def set_proxy_auth_username_password(self, username: str, password: str):
        self.proxy_auth = { "username": username, "password": password }
        
    def start_proxy(self):
        try:
            print("Starting SNAPI (Secure Network Application Interface) Proxy on port: "+ str(self.port))
            self.running = True

            self.cleanupThread = threading.Thread(target=self.cleanupThreads, daemon=True)
            self.cleanupThread.start()

            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.bind((self.host, self.port))
            self.socket.listen(self.max_threads)
            with self.sslContext.wrap_socket(self.socket, server_side=True) as sslSocket:
                while self.running:
                    clientSocket, clientAddress = sslSocket.accept()
                    if (len(self.active_threads) >= self.max_threads):
                        payload = {"message": "Proxy is busy"}
                        clientSocket.sendall(encode_packet(payload, 503))
                        clientSocket.close()
                    else:
                        request_thread = threading.Thread(target=self.process_client, args=(clientSocket, clientAddress), daemon=True)
                        request_thread.start()
                        self.active_threads.append(request_thread)
        except KeyboardInterrupt:
            print("\nSNAPI Proxy shutting down!")
            self.__suspendThreads()
        return

    def process_client(self, clientSocket: SSLSocket, clientAddress):
        data = None
        while True:
            try:
                new_data = clientSocket.recv(1024)
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

            #Proxy AUTH check
            if self.auth != None:
                proxy_auth = meta_inf["proxy_auth"]
                result = self.auth(proxy_auth)
                if result == False:
                    meta_inf = 401
                    payload = {"message": "Authentication failed"}
                    clientSocket.sendall(encode_packet(payload, meta_inf))
                    clientSocket.close()
                    return
            #get server host and port
            server_host = meta_inf["server"]
            server_port = meta_inf["server_port"]
            auth = ""
            if "auth" in meta_inf:
                auth = meta_inf["auth"]
            client = SNAPIClient(server_host, server_port, sslVerify=self.sslVerify, proxy_auth=self.proxy_auth, proxy=self.proxy, proxy_host=self.proxy_host, proxy_port=self.proxy_port)
            request_type = meta_inf["request_type"]
            response = None
            if request_type == "GET":
                response = client.get(meta_inf["route"], payload=payload, auth=auth)
            if request_type == "POST":
                response = client.post(meta_inf["route"], payload, auth=auth)
            if request_type == "DOWNLOAD":
                if "filename" not in payload:
                    meta = { "response_code": 400}
                    response = SNAPIResponse({"message": "No filename specified"}, meta)
                else:
                    response = client.download(meta_inf["route"], payload["filename"], auth=auth)

            response_code = 400
            response_payload = None
            if response != None:
                response_code = response.response_code()
                response_payload = response.payload()
            else:
                response_code = 400
                response_payload = {"message": "Bad Request"}

            clientSocket.sendall(encode_packet(response_payload, response_code))
            clientSocket.close()
            self.log_request(meta_inf["route"], response_code, clientAddress, request_type, server_host)

    def log_request(self, route, response_code, ipaddr, req_type, server):
        time = datetime.datetime.now()
        log_str = f"[{time}] {ipaddr[0]} -> {server} {response_code} {req_type} {route}"
        print(log_str)

    def log_error(self, errorMessage):
        print(f"[{datetime.datetime.now()}] {errorMessage}")

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