using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace ACMESharp.Protocol.Resources
{
    public class Identifier
    {
        [JsonPropertyName("type")]
        [JsonRequired]
        [Required]
        public string Type { get; set; }

        [JsonPropertyName("value")]
        [JsonRequired]
        [Required]
        public string Value { get; set; }
    }
}