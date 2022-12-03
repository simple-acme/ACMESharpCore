using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace ACMESharp.Protocol.Messages
{
    /// <summary>
    /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.3
    /// </summary>
    public class CreateAccountRequest
    {
        [JsonPropertyName("contact")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public IEnumerable<string> Contact { get; set; }

        [JsonPropertyName("termsOfServiceAgreed")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public bool? TermsOfServiceAgreed { get; set; }

        [JsonPropertyName("onlyReturnExisting")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public bool? OnlyReturnExisting  { get; set; }

        [JsonPropertyName("externalAccountBinding")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public object ExternalAccountBinding { get; set; }
    }
}
