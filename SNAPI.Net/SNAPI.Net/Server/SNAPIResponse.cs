using System;
namespace SNAPI.Net.Server
{
	public class SNAPIResponse
	{
		private int returnCode;
		private string encodedJsonPayload;

		public SNAPIResponse(int returnCode, string encodedJsonPayload="{}")
		{
			this.returnCode = returnCode;
			this.encodedJsonPayload = encodedJsonPayload;
		}

		public int GetReturnCode() { return this.returnCode; }
		public string GetPayload() { return this.encodedJsonPayload;  }
	}
}

