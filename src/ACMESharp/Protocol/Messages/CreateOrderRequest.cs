using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using ACMESharp.Protocol.Resources;

namespace ACMESharp.Protocol.Messages
{
    /// <summary>
    /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.4
    /// </summary>
    public class CreateOrderRequest
    {
        [JsonPropertyName("identifiers")]
        [JsonRequired]
        [Required, MinLength(1)]
        public Identifier[] Identifiers { get; set; }

        [JsonPropertyName("notBefore")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string NotBefore { get; set; }

        [JsonPropertyName("notAfter")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string NotAfter { get; set; }
    }
}