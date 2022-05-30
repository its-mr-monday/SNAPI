using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SNAPI.Net.Server
{
	public class SNAPIDownloadResponse
	{
		[JsonPropertyName("sha256")]
		public string Sha256 { get; set; } = "";

		[JsonPropertyName("filename")]
		public string Filename { get; set; } = "";

		[JsonPropertyName("filesize")]
		public int Filesize { get; set; } = 0;

		[JsonPropertyName("data")]
		public string Data { get; set; } = "";
	}
}

