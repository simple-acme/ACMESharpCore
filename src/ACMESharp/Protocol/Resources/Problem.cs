using System.Text.Json.Serialization;

namespace ACMESharp.Protocol.Resources
{
    public class Problem
    {
        public const string StandardProblemTypeNamespace = "urn:ietf:params:acme:error:";

        [JsonPropertyName("type")]
        public string? Type { get; set; }

        [JsonPropertyName("detail")]
        public string? Detail { get; set; }

        [JsonPropertyName("status")]
        public int? Status { get; set; }

        [JsonPropertyName("instance")]
        public string? Instance { get; set; }
    }
}
