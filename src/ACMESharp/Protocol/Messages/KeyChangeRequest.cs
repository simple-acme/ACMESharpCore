using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace ACMESharp.Protocol.Messages
{
    /// <summary>
    /// Based on:
    ///   https://tools.ietf.org/html/draft-ietf-acme-acme-18#section-7.3.5
    /// </summary>
    public class KeyChangeRequest
    {
        [JsonPropertyName("account")]
        [JsonRequired]
        [Required]
        public string Account { get; set; }

        [JsonPropertyName("oldKey")]
        [JsonRequired]
        [Required]
        public object OldKey { get; set; }
    }
}