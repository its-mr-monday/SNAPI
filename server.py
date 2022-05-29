from PySNAPI.SNAPIServer import SNAPIServer
from routes import *

def main():
    snapi = SNAPIServer("/Users/zack/Projects/SecureSocket/PySecureSocket/certs/server.crt", 
        "/Users/zack/Projects/SecureSocket/PySecureSocket/certs/server.key")
    snapi.add_route("/", index)
    snapi.add_route("/auth_check", auth_check)
    snapi.add_download("/download", "/Users/zack/Projects/SecureSocket/PySecureSocket/uploads", 
        authMethod=authVerify)
    snapi.serve(port=5001)

if __name__ == "__main__":
    main()