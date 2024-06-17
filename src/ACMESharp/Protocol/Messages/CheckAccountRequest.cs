using System.Diagnostics.CodeAnalysis;
using System.Text.Json.Serialization;

namespace ACMESharp.Protocol.Messages
{
    /// <summary>
    /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.3
    /// </summary>
    public class CheckAccountRequest
    {
        [JsonPropertyName("onlyReturnExisting")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        [SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "JSON serialization")]
        public bool OnlyReturnExisting  { get => true; }
    }
}