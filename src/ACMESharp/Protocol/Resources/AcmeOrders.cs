using System.Text.Json.Serialization;

namespace ACMESharp.Protocol.Resources
{
    public class AcmeOrders
    {
        public string? Next { get; set; }
        [JsonPropertyName("orders")]
        public string[]? Orders { get; set; }
    }
}