using System.Text.Json.Serialization;

namespace ACMESharp.Protocol.Messages
{
    /// <summary>
    /// https://datatracker.ietf.org/doc/draft-ietf-acme-ari/
    /// </summary>
    public class UpdateRenewalInfoRequest
    {
        /// <summary>
        /// The list of contact URLs.  Although a request to create a brand new account
        /// requires this value, when used in a request to lookup an existing account
        /// this property can be omitted.
        /// </summary>
        [JsonPropertyName("certID")]
        public string CertificateId { get; set; } = "";

        [JsonPropertyName("replaced")]
        public bool Replaced { get; set; } = true;
    }
}