using System.Text.Json.Serialization;

namespace ACMESharp.Protocol.Resources
{
    public class AcmeChallenge
    {
        [JsonPropertyName("type")]
        public string? Type { get; set; }

        [JsonPropertyName("url")]
        public string? Url { get; set; }

        [JsonPropertyName("status")]
        public string? Status { get; set; }

        /// <summary>
        /// The time at which the server validated this challenge,
        /// encoded in the format specified in RFC 3339 [RFC3339].
        /// This field is REQUIRED if the "status" field is "valid".
        /// </summary>
        [JsonPropertyName("validated")]
        public string? Validated { get; set; }

        /// <summary>
        /// Error that occurred while the server was validating the challenge,
        /// if any, structured as a problem document [RFC7807]. Multiple
        /// errors can be indicated by using subproblems Section 6.6.1.
        /// </summary>
        [JsonPropertyName("error")]
        public Problem? Error { get; set; }

        [JsonPropertyName("token")]
        public string? Token { get; set; }
    }
}