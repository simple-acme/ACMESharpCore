using System.Text.Json.Serialization;

namespace ACMESharp.Crypto.JOSE
{
    public static partial class JwsHelper
    {
        public class ProtectedHeader
        {
            [JsonPropertyName("alg")]
            public string? Algorithm { get; set; }

            [JsonPropertyName("url")]
            public string? Url { get; set; }

            [JsonPropertyName("nonce")]
            public string? Nonce { get; set; }

            [JsonPropertyName("kid")]
            public string? KeyIdentifier { get; set; }
        }

        public class ProtectedHeader<T> : ProtectedHeader
        {
            [JsonPropertyName("jwk")]
            public T? Key { get; set; }
        }
    }
}
