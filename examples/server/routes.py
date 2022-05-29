from auth import authVerify
from PySNAPI.SNAPIServer import SNAPIRequest
import os

def index(request: SNAPIRequest):
    request_type = request.request_type()
    if request_type !="GET":
        return 400, { "message": "Bad Request" }
    
    return 200, { "message": "welcome to the test SNAPI (Secure Network Application Interface)"}

def auth_check(request: SNAPIRequest):
    request_type = request.request_type()
    if request_type != "POST":
        return 400, { "message": "Bad Request" }
    payload = request.payload()
    meta_inf = request.meta_inf()
    if "auth" not in meta_inf:
        return 401, { "message": "Unauthorized" }
    
    if authVerify(meta_inf["auth"]) == False:
        return 401, { "message": "Unauthorized" }

    if "username" not in payload:
        return 400, { "message": "Bad Request" }

    if payload["username"] != "test":
        return 401, { "message": "Unauthorized" }

    return 200, { "message": "Authorized" }

def get_files(request: SNAPIRequest):
    request_type = request.request_type()
    if request_type != "GET":
        return 400, { "message": "Bad Request" }
    payload = request.payload()
    meta_inf = request.meta_inf()
    if "auth" not in meta_inf:
        return 401, { "message": "Unauthorized" }
    
    if authVerify(meta_inf["auth"]) == False:
        return 401, { "message": "Unauthorized" }

    if "username" not in payload:
        return 400, { "message": "Bad Request" }

    if payload["username"] != "test":
        return 401, { "message": "Unauthorized" }

    files = os.listdir("/Users/zack/Projects/SecureSocket/PySecureSocket/uploads")
    for file in files:
        if os.path.isfile(os.path.join("/Users/zack/Projects/SecureSocket/PySecureSocket/uploads", file)):
            pass
        files.remove(file)
    
    return 200, { "files": files }

    