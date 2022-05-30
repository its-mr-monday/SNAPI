using System;
using SNAPI.Net.Server;

namespace SNAPI.Net.SmapleServer
{
	public class Routes
	{
		private static bool CheckAuth(string token)
        {
			if (token == "TEST_TOKEN_FF70") return true;
			return false;
        }
		public static SNAPIResponse Index(SNAPIRequest request)
        {
			return new SNAPIResponse(200, encodedJsonPayload: "{\"message\": \"Welcome to the test SNAPI (Secure Network Application Interface\"}");
        }

		public static SNAPIResponse IsAuth(SNAPIRequest request)
        {
			SNAPIRequestMetaData? meta = request.GetRequestMetaDataObject();
			if (meta.Request_type != "POST")
            {

            }
			if (meta != null)
            {
				string auth = meta.Auth;
				if (auth != "")
                {
					if (CheckAuth(auth)) { return new SNAPIResponse(200, encodedJsonPayload: "{\"message\": \"Authorized\"}"); }
                }
            }
			return new SNAPIResponse(401, encodedJsonPayload: "{\"message\": \"Unauthorized\"}");

        }
	}
}

