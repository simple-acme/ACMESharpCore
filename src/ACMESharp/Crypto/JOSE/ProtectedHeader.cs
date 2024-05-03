using System.Text.Json.Serialization;

namespace ACMESharp.Crypto.JOSE
{
    public static partial class JwsHelper
    {
        public class ProtectedHeader
        {
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
            [JsonPropertyName("alg")]
            public string? Algorithm { get; set; }

            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
            [JsonPropertyName("url")]
            public string? Url { get; set; }

            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
            [JsonPropertyName("nonce")]
            public string? Nonce { get; set; }

            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
            [JsonPropertyName("kid")]
            public string? KeyIdentifier { get; set; }
        }

        public class ProtectedHeader<T> : ProtectedHeader
        {
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
            [JsonPropertyName("jwk")]
            public T? Key { get; set; }
        }
    }
}
