using ACMESharp.Protocol.Resources;

namespace ACMESharp.Protocol
{
    /// <summary>
    /// An aggregation of AcmeOrder details including resource payload and ancillary,
    /// associated data.
    /// </summary>
    /// <remarks>
    /// This represents a superset of details that are included in responses
    /// to several ACME operations regarding an ACME AcmeOrder, such as 
    /// AcmeOrder creation and finalization.
    /// </remarks>
    public class AcmeOrderDetails(AcmeOrder payload)
    {
        public AcmeOrder Payload { get; set; } = payload;

        public string? OrderUrl { get; set; }
    }
}