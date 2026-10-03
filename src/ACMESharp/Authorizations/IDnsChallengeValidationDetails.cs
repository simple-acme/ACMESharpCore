namespace ACMESharp.Authorizations
{
    public interface IDnsChallengeValidationDetails : IChallengeValidationDetails
    {
        string DnsRecordName { get; set; }
        string DnsRecordType { get; set; }
        string DnsRecordValue { get; set; }
    }
}