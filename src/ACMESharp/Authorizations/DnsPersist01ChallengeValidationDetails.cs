namespace ACMESharp.Authorizations
{
    /// <summary>
    /// https://www.ietf.org/archive/id/draft-ietf-acme-dns-persist-02.html
    /// </summary>
    public record struct DnsPersist01ChallengeValidationDetails : IDnsChallengeValidationDetails
    {
        public const string DnsPersist01ChallengeType = "dns-persist-01";
        public const string DnsRecordNamePrefix = "_validation-persist";
        public const string DnsRecordTypeDefault = "TXT";
        public readonly string ChallengeType => DnsPersist01ChallengeType;
        public string DnsRecordName { get; set; }
        public string DnsRecordType { get; set; }
        public string DnsRecordValue { get; set; }  
        public string[] IssuerDomainNames { get; set; }
    }
}