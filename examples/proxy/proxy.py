from PySNAPI.SNAPIProxy import SNAPIProxy

def auth(proxy_auth: dict):
    if "token" in proxy_auth:
        if proxy_auth["token"] == "PROXY_TEST_TOKEN":
            return True
    
    if "username" in proxy_auth and "password" in proxy_auth:
        if proxy_auth["username"] == "test" and proxy_auth["password"] == "test":
            return True
    return False

def main():
    proxy = SNAPIProxy("/Users/zack/Projects/SecureSocket/PySecureSocket/certs/server.crt", 
        "/Users/zack/Projects/SecureSocket/PySecureSocket/certs/server.key", auth=auth, sslVerify=False)
    proxy.start_proxy()

if __name__ == "__main__":
    main()