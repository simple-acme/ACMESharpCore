using System.Text.Json.Serialization;
using static ACMESharp.Crypto.RsaTool;

namespace ACMESharp
{
    [JsonSerializable(typeof(RsaKeys))]
    internal partial class AcmeJson : JsonSerializerContext
    {
    }
}
