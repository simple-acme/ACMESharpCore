using System.Text.Json;
using System.Text.Json.Serialization;
using ACMESharp.Protocol.Resources;
using static ACMESharp.Crypto.JOSE.Impl.ESJwsTool;
using static ACMESharp.Crypto.JOSE.Impl.RSJwsTool;

namespace ACMESharp
{
    [JsonSerializable(typeof(RSJwk))]
    [JsonSerializable(typeof(ESJwk))]
    [JsonSerializable(typeof(ESPrivateExport))]
    [JsonSerializable(typeof(Problem))]
    [JsonSerializable(typeof(Order))]
    [JsonSerializable(typeof(ServiceDirectory))]
    [JsonSerializable(typeof(Account))]
    [JsonSerializable(typeof(Authorization))]
    internal partial class AcmeJson : JsonSerializerContext
    {
        public static AcmeJson Insensitive
        {
            get
            {
                return new AcmeJson(new JsonSerializerOptions() { PropertyNameCaseInsensitive = true });
            }
        }
    }
}
