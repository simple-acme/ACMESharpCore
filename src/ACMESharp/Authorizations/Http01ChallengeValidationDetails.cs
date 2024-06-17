namespace ACMESharp.Authorizations
{
    /// <summary>
    /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-8.3
    /// </summary>
    public record struct Http01ChallengeValidationDetails : IChallengeValidationDetails
    {
        public const string Http01ChallengeType = "http-01";
        // URL template:
        //  "http://{domain}/.well-known/acme-challenge/{token}"
        public const string HttpPathPrefix = ".well-known/acme-challenge";
        public const string HttpResourceContentTypeDefault = "application/octet-stream";

        public readonly string ChallengeType => Http01ChallengeType;

        public string HttpResourceUrl { get; set; }

        public string HttpResourcePath { get; set; }

        public string HttpResourceContentType { get; set; }

        public string HttpResourceValue { get; set; }
    }
}