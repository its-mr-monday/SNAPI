using System.Text.Json.Serialization;

namespace SNAPI.Net.Client
{
    public class SNAPIFilePayload
    {
        [JsonPropertyName("filename")]
        public string Filename { get; set; } = "";

        [JsonPropertyName("filesize")]
        public int Filesize { get; set; } = 0;

        [JsonPropertyName("data")]
        public string Data { get; set; } = "";

        [JsonPropertyName("sha256")]
        public string Sha256 { get; set; } = "";

    }

}

