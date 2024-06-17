using System.Diagnostics.CodeAnalysis;
using System.Text.Json.Serialization;

namespace ACMESharp.Protocol.Messages
{
    /// <summary>
    /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.5.2
    /// </summary>
    public class DeactivateAuthorizationRequest
    {
        [JsonPropertyName("status")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        [SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "JSON serialization")]
        public string Status { get => "deactivated"; }
    }
}