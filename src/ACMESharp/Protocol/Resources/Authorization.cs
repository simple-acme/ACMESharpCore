using System.ComponentModel.DataAnnotations;
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
        [Required]
        public Identifier Identifier { get; set; }

        [JsonPropertyName("status")]
        [JsonRequired]
        [Required]
        public string Status { get; set; }

        [JsonPropertyName("expires")]
        public string Expires { get; set; }

        [JsonPropertyName("challenges")]
        [JsonRequired]
        [Required]
        public Challenge[] Challenges { get; set; }

        [JsonPropertyName("wildcard")]
        public bool? Wildcard { get; set; }
    }
}