using System.Text.Json.Serialization;

namespace ACMESharp.Crypto.JOSE
{
    public class JwsSignedPayload
    {
        [JsonPropertyName("header")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public object Header { get; set; }

        [JsonPropertyName("protected")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string Protected { get; set; }

        [JsonPropertyName("payload")]
        [JsonRequired]
        public string Payload { get; set; }

        [JsonPropertyName("signature")]
        [JsonRequired]
        public string Signature { get; set; }
    }
}