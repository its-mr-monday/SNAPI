using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SNAPI.Net.Server
{
    public class SNAPIDownloadRequest
    {
        [JsonPropertyName("filename")]
        public string Filename { get; set; } = "";
    }
}

