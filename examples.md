## SNAPI Packet Examples

## Simple Packet
A basic SNAPI (Secure Network Application Interface) Protocol request packet has the 
following shape:

    <snapi_req>
        <meta>
            *JSON FIELD REPRESENTING META DATA OF REQUEST*
        </meta>
        <payload>
            *JSON PAYLOAD REPRESENTING BODY OF REQUEST*
        </payload>
    </snapi_req>

A basic SNAPI (Secure Network Application Interface) Protocol response packet has the
following shape:

    <snapi_res>
        <meta>
            *JSON FIELD REPRESENTING META DATA OF RESPONSE*
        </meta>
        <payload>
            *JSON FIELD REPRESENTING BODY OF RESPONSE*
        </payload>
    </snapi_res>

### GET REQUEST EXAMPLES

#### SNAPI Get Request (No Proxy) no authentication
The following demonstrates the form of a SNAPI GET request packet with no authentication

    <snapi_req>
        <meta>
        {
            "request_type": "GET",
            "route": "/snapi/v1/getusers"
        }
        </meta>
        <payload>{}</payload>
    </snapi_req>

#### SNAPI Get Request (No Proxy) server side authentication
The following demonstrates the form of a SNAPI GET request packet with a server auth token

    <snapi_req>
        <meta>
        {
            "request_type": "GET",
            "route": "/snapi/v1/getusers",
            "auth": "TOKEN_HERE"
        }
        </meta>
        <payload>{}</payload>
    </snapi_req>

#### SNAPI Get Request (Proxy no auth) server side authentication
The following packet demonstrates the form of a SNAPI GET request packet with a server
auth token that is being proxied through a SNAPI Proxy with authentication disabled

    <snapi_req>
        <meta>
        {
            "request_type": "GET",
            "route": "/snapi/v1/getusers",
            "server_host": "127.0.0.1",
            "server_port": 5001,
            "auth": "TOKEN_HERE"
        }
        </meta>
        <payload>{}</payload>
    </snapi_req>

#### SNAPI Get Request (Proxy with auth) server side authentication
The following packet demonstrates the form of a SNAPI GET request packet with a server
auth token that is being proxied through a SNAPI Proxy with authentication enabled,
proxy authentication being used is token authentication

    <snapi_req>
        <meta>
        {
            "request_type": "GET",
            "route": "/snapi/v1/getusers",
            "server_host": "127.0.0.1",
            "server_port": 5001,
            "auth": "TOKEN_HERE",
            "proxy_auth": {
                "token": "PROXY_TOKEN_HERE"
            }
        }
        </meta>
        <payload>{}</payload>
    </snapi_req>

#### SNAPI Get Response
The following packet demonstrates the form of a SNAPI GET response packet

    <snapi_res>
        <meta>
        {
            "response_code": 200
        }
        </meta>
        <payload>
        {
            "message" : "Succesfully fetched 1 user",
            "length": 1,
            "users" : {
                "test" : {
                    "id" : 0,
                    "posts" : 10
                }
            }
        }
        </payload>
    </snapi_res>

## SNAPI POST REQUEST EXAMPLES

#### SNAPI POST Request (No Proxy) no authentication
