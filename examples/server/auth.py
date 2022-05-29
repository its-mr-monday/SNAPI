
def authVerify(auth_token: str):
    #For this example we are using our test TOKEN
    #You could run some database commands here or provide a cache object to verify the token
    if auth_token == "TEST_TOKEN_FF70":
        return True
    return False