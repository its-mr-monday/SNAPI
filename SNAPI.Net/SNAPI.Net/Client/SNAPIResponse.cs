using System;
using System.Text.Json;

namespace SNAPI.Net.Client
{
	public class SNAPIResponse
	{
		private string payload;
		private string meta;
		private SNAPIResponseMetaData? metaData;

		public SNAPIResponse(string meta, string payload)
		{
			this.meta = meta;
			this.payload = payload;
			this.metaData = JsonSerializer.Deserialize<SNAPIResponseMetaData>(meta);
		}

		public string GetPayload()
        {
			return this.payload;
        }

		public string GetMetaInf()
        {
			return this.meta;
        }

		public SNAPIResponseMetaData? GetMetaObject()
        {
			return this.metaData;
        }

		public int GetResponseCode()
        {
			if (metaData != null)
			{
				return metaData.Response_code;
			} else
            {
				return 400;	//If it is null we will assume Bad Request
            }
        }
	}
}

