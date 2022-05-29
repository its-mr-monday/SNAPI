from PySNAPI.SNAPIClient import SNAPIClient, SNAPIResponse, socket, ssl, json
from PySNAPI.SNAPIServer import encode_packet, decode_packet, threading, time
from ssl import SSLSocket

class SNAPIProxy:
    def __init__(self, pem_file: str, private_key: str, host="0.0.0.0", port=5002, max_threads=50, sslVerify=True, proxy=None, proxy_host=None, proxy_port=None):
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
        self.set_proxy(proxy, proxy_host, proxy_port)

    def set_proxy(self, proxy: str, proxy_host: str, proxy_port: int):
        self.proxy = proxy
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port

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
                        meta_inf = {"response_code": 503 }
                        payload = {"message": "Proxy is busy"}
                        clientSocket.sendall(encode_packet(meta_inf, payload))
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
            #get server host and port
            server_host = meta_inf["server"]
            server_port = meta_inf["server_port"]
            auth = ""
            if "auth" in meta_inf:
                auth = meta_inf["auth"]
            client = SNAPIClient(server_host, server_port, sslVerify=self.sslVerify, proxy=self.proxy, proxy_host=self.proxy_host, proxy_port=self.proxy_port)
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

            print(encode_packet(response_payload, response_code).decode("utf-8"))
            clientSocket.sendall(encode_packet(response_payload, response_code))
            clientSocket.close()

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