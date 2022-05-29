using System;
namespace SNAPI.Net.SNAPIClient
{
	public class SNAPIResponse
	{
		private string payload;
		private string meta;
		public SNAPIResponse(string meta, string payload)
		{
			this.meta = meta;
			this.payload = payload;
		}

		public string GetPayload()
        {
			return this.payload;
        }

		public string GetMetaInf()
        {
			return this.meta;
        }
	}
}

