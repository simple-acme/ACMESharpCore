using System;
using System.Text.Json.Serialization;

namespace ACMESharp.Protocol.Resources
{
    public class AcmeRenewalInfo
    {
        [JsonPropertyName("suggestedWindow")]
        [JsonRequired]
        public AcmeRenewalInfoSuggestedWindow SuggestedWindow { get; set; } = new();

        [JsonPropertyName("explanationURL")]
        public string ExplanationUrl { get; set; } = "";
    }

    public class AcmeRenewalInfoSuggestedWindow
    {
        [JsonPropertyName("start")]
        [JsonRequired]
        public DateTime? Start { get; set; } = null;

        [JsonPropertyName("end")]
        [JsonRequired]
        public DateTime? End { get; set; } = null;
    }
}