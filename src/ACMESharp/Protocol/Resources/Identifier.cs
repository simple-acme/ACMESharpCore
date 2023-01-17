using System.Text.Json.Serialization;

namespace ACMESharp.Protocol.Resources
{
    public class Identifier
    {
        [JsonPropertyName("type")]
        [JsonRequired]
        public string Type { get; set; }

        [JsonPropertyName("value")]
        [JsonRequired]
        public string Value { get; set; }
    }
}