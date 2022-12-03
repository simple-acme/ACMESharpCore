using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace ACMESharp.Protocol.Messages
{
    /// <summary>
    /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.3
    /// </summary>
    public class FinalizeOrderRequest
    {
        [JsonPropertyName("csr")]
        [JsonRequired]
        [Required]
        public string Csr { get; set; }
    }
}