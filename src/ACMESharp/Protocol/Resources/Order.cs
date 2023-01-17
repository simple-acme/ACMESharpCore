using System.Text.Json.Serialization;

namespace ACMESharp.Protocol.Resources
{
    /// <summary>
    /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.1.3
    /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.3
    /// </summary>
    public class Order
    {
        [JsonPropertyName("status")]
        public string Status { get; set; }

        [JsonPropertyName("expires")]
        public string Expires { get; set; }

        [JsonPropertyName("notBefore")]
        public string NotBefore { get; set; }

        [JsonPropertyName("notAfter")]
        public string NotAfter { get; set; }

        [JsonPropertyName("identifiers")]
        public Identifier[] Identifiers { get; set; }

        [JsonPropertyName("authorizations")]
        public string[] Authorizations { get; set; }

        [JsonPropertyName("finalize")]
        [JsonRequired]
        public string Finalize { get; set; }

        [JsonPropertyName("certificate")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string Certificate { get; set; }

        [JsonPropertyName("error")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public Problem Error { get; set; }
    }
}