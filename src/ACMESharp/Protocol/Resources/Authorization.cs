using System.Text.Json.Serialization;

namespace ACMESharp.Protocol.Resources
{
    /// <summary>
    /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.1.4
    /// </summary>
    public class Authorization
    {
        [JsonPropertyName("identifier")]
        [JsonRequired]
        public Identifier Identifier { get; set; }

        [JsonPropertyName("status")]
        [JsonRequired]
        public string Status { get; set; }

        [JsonPropertyName("expires")]
        public string Expires { get; set; }

        [JsonPropertyName("challenges")]
        [JsonRequired]
        public Challenge[] Challenges { get; set; }

        [JsonPropertyName("wildcard")]
        public bool? Wildcard { get; set; }
    }
}