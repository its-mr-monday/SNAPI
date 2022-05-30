using System;
using System.Text.Json;

namespace SNAPI.Net.Server
{
	public class SNAPIRequest
	{
		private string req_meta_json;
		private string req_payload_json;
		private SNAPIRequestMetaData? req_meta;

		public SNAPIRequest(string meta_json, string payload_json)
		{
			this.req_meta_json = meta_json;
			this.req_payload_json = payload_json;
			this.req_meta = JsonSerializer.Deserialize<SNAPIRequestMetaData>(meta_json);
		}

		public string GetRequestMetaData() { return this.req_meta_json; }

		public SNAPIRequestMetaData? GetRequestMetaDataObject() { return this.req_meta; }

		public string GetJsonPayload()
        {
			return this.req_payload_json;
        }
        
	}
}

