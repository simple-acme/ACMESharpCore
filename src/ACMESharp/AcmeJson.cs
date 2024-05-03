using System.Text.Json;
using System.Text.Json.Serialization;
using ACMESharp.Crypto.JOSE;
using ACMESharp.Protocol.Messages;
using ACMESharp.Protocol.Resources;
using static ACMESharp.Crypto.JOSE.Impl.ESJwsTool;
using static ACMESharp.Crypto.JOSE.Impl.RSJwsTool;
using static ACMESharp.Crypto.JOSE.JwsHelper;

namespace ACMESharp
{
    [JsonSerializable(typeof(RSJwk))]
    [JsonSerializable(typeof(ESJwk))]
    [JsonSerializable(typeof(ESPrivateExport))]
    [JsonSerializable(typeof(Problem))]
    [JsonSerializable(typeof(AcmeOrder))]
    [JsonSerializable(typeof(JwsSignedPayload))]
    [JsonSerializable(typeof(ServiceDirectory))]
    [JsonSerializable(typeof(Account))]
    [JsonSerializable(typeof(AcmeAuthorization))]
    [JsonSerializable(typeof(KeyChangeRequest<RSJwk>))]
    [JsonSerializable(typeof(KeyChangeRequest<ESJwk>))]
    [JsonSerializable(typeof(ProtectedHeader<RSJwk>))]
    [JsonSerializable(typeof(ProtectedHeader<ESJwk>))]
    [JsonSerializable(typeof(CreateAccountRequest))]
    [JsonSerializable(typeof(CheckAccountRequest))]
    [JsonSerializable(typeof(AcmeRenewalInfo))]
    [JsonSerializable(typeof(UpdateAccountRequest))]
    [JsonSerializable(typeof(UpdateRenewalInfoRequest))]
    [JsonSerializable(typeof(DeactivateAuthorizationRequest))]
    [JsonSerializable(typeof(CreateOrderRequest))]
    [JsonSerializable(typeof(FinalizeOrderRequest))]
    [JsonSerializable(typeof(RevokeCertificateRequest))]
    [JsonSerializable(typeof(ProtectedHeader))]
    public partial class AcmeJson : JsonSerializerContext
    {
        public static AcmeJson Insensitive
        {
            get
            {
                return new AcmeJson(
                    new JsonSerializerOptions() { 
                        PropertyNameCaseInsensitive = true, 
                        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingDefault 
                    });
            }
        }
    }
}
