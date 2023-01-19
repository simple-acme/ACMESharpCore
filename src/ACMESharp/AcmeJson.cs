using System.Text.Json;
using System.Text.Json.Serialization;
using ACMESharp.Crypto.JOSE;
using ACMESharp.Protocol.Messages;
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
    [JsonSerializable(typeof(JwsSignedPayload))]
    [JsonSerializable(typeof(ServiceDirectory))]
    [JsonSerializable(typeof(Account))]
    [JsonSerializable(typeof(Authorization))]
    [JsonSerializable(typeof(KeyChangeRequest<RSJwk>))]
    [JsonSerializable(typeof(KeyChangeRequest<ESJwk>))]
    [JsonSerializable(typeof(CreateAccountRequest))]
    [JsonSerializable(typeof(CheckAccountRequest))]
    [JsonSerializable(typeof(UpdateAccountRequest))]
    [JsonSerializable(typeof(DeactivateAuthorizationRequest))]
    [JsonSerializable(typeof(CreateOrderRequest))]
    [JsonSerializable(typeof(FinalizeOrderRequest))]
    [JsonSerializable(typeof(RevokeCertificateRequest))]
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
