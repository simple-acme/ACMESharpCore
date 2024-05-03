using System.Text.Json.Serialization;
using ACMESharp.Protocol.Resources;

namespace ACMESharp.Protocol.Messages
{
    /// <summary>
    /// https://tools.ietf.org/html/draft-ietf-acme-acme-18#section-7.6
    /// </summary>
    public class RevokeCertificateRequest
    {
        [JsonPropertyName("certificate")]
        [JsonRequired]
        public string? Certificate { get; set; }

        [JsonPropertyName("reason")]
        public RevokeReason Reason { get; set; }
    }
}