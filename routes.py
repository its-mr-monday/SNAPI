
def authVerify(auth_token: str):
    #For this example we are using our test TOKEN
    #You could run some database commands here or provide a cache object to verify the token
    if auth_token == "TEST_TOKEN_FF70":
        return True
    return False

#Route '/' filters for only GET requests
def index(request_type: str, request_data: dict):
    if request_type !="GET":
        return 400, { "message": "Bad Request" }
    payload = request_data["payload"]
    meta_inf = request_data["meta_inf"]
    return 200, { "message": "welcome to the test SST server api"}

#Route '/auth_check' filters for only POST requests
def auth_check(request_type: str, request_data: dict):
    if request_type != "POST":
        return 400, { "message": "Bad Request" }
    payload = request_data["payload"]
    meta_inf = request_data["meta_inf"]
    if "auth" not in meta_inf:
        return 401, { "message": "Unauthorized" }
    
    if meta_inf["auth"] != "TEST_TOKEN_FF70":
        return 401, { "message": "Unauthorized" }

    if "username" not in payload:
        return 400, { "message": "Bad Request" }

    if payload["username"] != "test":
        return 401, { "message": "Unauthorized" }
    
    return 200, { "message": "Authorized" }
'''
#Route '/download' filters for only DOWNLOAD_SETUP / DOWNLOAD_PART requests
def download(request_type: str, request_data: dict):
    current_dir = os.getcwd()
    if request_type != "DOWNLOAD_SETUP" or request_type != "DOWNLOAD_PART":
        return 400, { "message": "Bad Request" }
    payload = request_data["payload"]
    meta_inf = request_data["meta_inf"]
    if "auth" not in meta_inf:
        return 401, { "message": "Unauthorized" }
    if meta_inf["auth"] != "TEST_TOKEN_FF70":
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
    if len(b64FileString) % buffer != 0:
        parts += 1

    if request_type == "DOWNLOAD_SETUP":
        #Setup the file for upload
        if payload["filename"] != "test.txt":
            return 401, { "message": "Unauthorized" }
        sha = hashlib.sha256(filebytes).hexdigest()
        return 200, { "message": "File setup", "filesize": "100", "parts": "5", "sha": "123456789", "buffer": "100", "status": "proceed" }

    elif request_type == "DOWNLOAD_PART":
        #Get the file part
        if "part" not in payload:
            return 400, { "message": "Bad Request" }
        if payload["part"] < 1 or payload["part"] > 3:
            return 400, { "message": "Bad Request" }
        if payload["part"] == 1:
            return 200, { "data": base64.b64encode(b"Hello World").decode("utf-8"), "parts": 3, "sha": "sha256", "buffer": "4096", "status": "proceed" }
        elif payload["part"] == 2:
            return 200, { "data": base64.b64encode(b"Hello World").decode("utf-8"), "parts": 3, "sha": "sha256", "buffer": "4096", "status": "proceed" }
        elif payload["part"] == 3:
            return 200, { "data": base64.b64encode(b"Hello World").decode("utf-8"), "parts": 3, "sha": "sha256", "buffer": "4096", "status": "proceed" }
'''