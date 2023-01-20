using System.Text.Json.Serialization;

namespace ACMESharp.Protocol.Resources
{
    public class AcmeIdentifier
    {
        [JsonPropertyName("type")]
        [JsonRequired]
        public string Type { get; set; } = "";

        [JsonPropertyName("value")]
        [JsonRequired]
        public string Value { get; set; } = "";
    }
}