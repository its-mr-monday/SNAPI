using System.Text.Json.Serialization;

namespace SNAPI.Net.SNAPIClient
{
	public class SNAPIResponseMetaData
	{
		[JsonPropertyName("response_code")]
		public int Response_code { get; set; } = 400;

	}
}

