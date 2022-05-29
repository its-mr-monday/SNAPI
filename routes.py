from PySNAPI.SNAPIServer import SNAPIRequest

def authVerify(auth_token: str):
    #For this example we are using our test TOKEN
    #You could run some database commands here or provide a cache object to verify the token
    if auth_token == "TEST_TOKEN_FF70":
        return True
    return False

#Route '/' filters for only GET requests for any user
def index(request: SNAPIRequest):
    request_type = request.request_type()
    if request_type !="GET":
        return 400, { "message": "Bad Request" }
    
    return 200, { "message": "welcome to the test SNAPI (Secure Network Application Interface)"}

#Route '/auth_check' filters for only POST requests for authed users
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