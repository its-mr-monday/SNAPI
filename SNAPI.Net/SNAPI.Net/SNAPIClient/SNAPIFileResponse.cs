using System;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SNAPI.Net.SNAPIClient
{
	public class SNAPIFileResponse
	{
		[JsonPropertyName("filename")]
		public string Filename { get; set; } = "";

		[JsonPropertyName("data")]
		public string Data { get; set; } = "";

		[JsonPropertyName("filesize")]
		public int Filesize { get; set; } = 0;

		[JsonPropertyName("sha256")]
		public string Sha256 { get; set; } = "";

	}
}

