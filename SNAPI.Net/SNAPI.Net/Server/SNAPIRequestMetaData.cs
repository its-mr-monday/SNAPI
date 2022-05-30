using System;
using System.Text.Json.Serialization;

namespace SNAPI.Net.Server
{
	public class SNAPIRequestMetaData
	{
		[JsonPropertyName("route")]
		public string Route { get; set; } = "";

		[JsonPropertyName("auth")]
		public string Auth { get; set; } = "";

		[JsonPropertyName("request_type")]
		public string Request_type { get; set; } = "";

	}
}

