from PySNAPI.SNAPIProxy import SNAPIProxy

def main():
    proxy = SNAPIProxy("/Users/zack/Projects/SecureSocket/PySecureSocket/certs/server.crt", 
        "/Users/zack/Projects/SecureSocket/PySecureSocket/certs/server.key", sslVerify=False)
    proxy.start_proxy()

if __name__ == "__main__":
    main()