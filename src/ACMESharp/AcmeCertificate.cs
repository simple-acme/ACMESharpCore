using ACMESharp.HTTP;

namespace ACMESharp
{
    public record struct AcmeCertificate
    {
        public byte[] Certificate { get; set; }
        public LinkCollection Links { get; set; }
    }
}
