from PySNAPI.SNAPIClient import SNAPIResponse, SNAPIClient, SNAPIProxyConfig, get_file, write_file

def main():
    proxyConf = SNAPIProxyConfig("127.0.0.1", 5002, proxy_username_and_password={"username": "test", "password": "test"})
    apiClient = SNAPIClient("127.0.0.1", 5001, sslVerify=False, proxy_config=proxyConf)
    #apiClient.set_proxy_auth_token("PROXY_TEST_TOKEN")
    response = apiClient.get("/")
    if (response.response_code() == None or response.payload() == None):
        print("Error")
    else:
        print(response.response_code())
        print(response.payload())

    response2 = apiClient.post("/auth_check", {"username": "test"}, auth="TEST_TOKEN_FF70")
    if (response2.response_code() == None or response2.payload() == None):

        print("Error")
    else:
        print(response2.response_code())
        print(response2.payload())

    response3 = apiClient.post("/auth_check", {})
    print(response3.response_code())
    print(response3.payload())
    
    response3 = apiClient.download("/download", "test.txt", auth="TEST_TOKEN_FF70")
    if response3 == False:
        print("Error failed to download!")
    else:
        filename, filebytes = get_file(response3)
        print("Downloaded file: "  + filename)
        print("Success!")
    
if __name__ == "__main__":
    main()