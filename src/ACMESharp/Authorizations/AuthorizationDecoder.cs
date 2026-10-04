using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using ACMESharp.Crypto;
using ACMESharp.Crypto.JOSE;
using ACMESharp.Protocol;
using ACMESharp.Protocol.Resources;

namespace ACMESharp.Authorizations
{
    public class AuthorizationDecoder
    {

        /// <summary>
        /// </summary>
        /// <remarks>
        /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-8
        /// </remarks>
        public static IChallengeValidationDetails DecodeChallengeValidation(AcmeAuthorization authz, string challengeType, IJwsTool signer, AccountDetails? account, DirectoryMeta? directoryMeta)
        {
            var challenge = authz.Challenges?.Where(x => x.Type == challengeType).FirstOrDefault();
            if (challenge == default)
            {
                throw new InvalidOperationException($"Challenge type [{challengeType}] not found for given Authorization");
            }
            return challengeType switch
            {
                Dns01ChallengeValidationDetails.Dns01ChallengeType => ResolveChallengeForDns01(authz, challenge, signer),
                DnsPersist01ChallengeValidationDetails.DnsPersist01ChallengeType => ResolveChallengeForDnsPersist01(authz, challenge, signer, account, directoryMeta),
                Http01ChallengeValidationDetails.Http01ChallengeType => ResolveChallengeForHttp01(authz, challenge, signer),
                TlsAlpn01ChallengeValidationDetails.TlsAlpn01ChallengeType => ResolveChallengeForTlsAlpn01(challenge, signer),
                _ => throw new NotImplementedException($"Unknown or unsupported Challenge type [{challengeType}]"),
            };
        }

        public static DnsPersist01ChallengeValidationDetails ResolveChallengeForDnsPersist01(AcmeAuthorization authz, AcmeChallenge c, IJwsTool signer, AccountDetails? account, DirectoryMeta? directoryMeta)
        {
            var x = new DnsPersist01ChallengeValidationDetails
            {
                DnsRecordName = $"{DnsPersist01ChallengeValidationDetails.DnsRecordNamePrefix}.{authz.Identifier}",
                DnsRecordType = DnsPersist01ChallengeValidationDetails.DnsRecordTypeDefault,
                IssuerDomainNames = c?.IssuerDomainNames ?? throw new InvalidOperationException($"Challenge type [{DnsPersist01ChallengeValidationDetails.DnsPersist01ChallengeType}] is missing required IssuerDomainNames property")
            };
            if (c.IssuerDomainNames == null || c.IssuerDomainNames.Length == 0)
            {
                throw new InvalidOperationException($"Challenge type [{DnsPersist01ChallengeValidationDetails.DnsPersist01ChallengeType}] is missing required IssuerDomainNames property");
            }

            // Specification:
            // https://datatracker.ietf.org/doc/html/draft-ietf-acme-dns-persist-02#section-10.2

            var hashBytes = new List<byte>();
            var domain = $"{authz?.Identifier}";
            hashBytes.Add((byte)domain.Length);
            hashBytes.AddRange(Encoding.ASCII.GetBytes(domain));
            hashBytes.AddRange(JwsHelper.ComputeThumbprint(signer));
            hashBytes.AddRange(Encoding.ASCII.GetBytes(account?.Kid ?? throw new InvalidOperationException("Missing account KID")));

            var sha256hash = SHA256.HashData([.. hashBytes]);
            var hash = Base64Tool.UrlEncode(sha256hash);

            var prefix = directoryMeta?.AccountHashPrefix ?? throw new InvalidOperationException("Missing account hash prefix.");
            x.DnsRecordValue = $"{c.IssuerDomainNames.First()}; accounturi={prefix}sha256/{hash}";

            return x;
        }

        /// <summary>
        /// </summary>
        /// <remarks>
        /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-8.4
        /// </remarks>
        public static Dns01ChallengeValidationDetails ResolveChallengeForDns01(AcmeAuthorization authz, AcmeChallenge challenge, IJwsTool signer)
        {
            var keyAuthzDigested = JwsHelper.ComputeKeyAuthorizationDigest(signer, challenge?.Token);
            return new Dns01ChallengeValidationDetails
            {
                DnsRecordName = $"{Dns01ChallengeValidationDetails.DnsRecordNamePrefix}.{authz.Identifier?.Value}",
                DnsRecordType = Dns01ChallengeValidationDetails.DnsRecordTypeDefault,
                DnsRecordValue = keyAuthzDigested,
            };
        }

        /// <summary>
        /// </summary>
        /// <remarks>
        /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-8.3
        /// </remarks>
        public static Http01ChallengeValidationDetails ResolveChallengeForHttp01(
                AcmeAuthorization authz, AcmeChallenge challenge, IJwsTool signer)
        {
            var keyAuthz = JwsHelper.ComputeKeyAuthorization(signer, challenge.Token);

            return new Http01ChallengeValidationDetails
            {
                HttpResourceUrl = $@"http://{authz.Identifier?.Value}/{Http01ChallengeValidationDetails.HttpPathPrefix}/{challenge.Token}",
                HttpResourceName = $@"{challenge.Token}",
                HttpResourceContentType = Http01ChallengeValidationDetails.HttpResourceContentTypeDefault,
                HttpResourceValue = keyAuthz,
            };
        }

        /// <summary>
        /// </summary>
        /// <remarks>
        /// https://tools.ietf.org/html/draft-ietf-acme-tls-alpn-05
        /// </remarks>
        public static TlsAlpn01ChallengeValidationDetails ResolveChallengeForTlsAlpn01(AcmeChallenge challenge, IJwsTool signer)
        {
            var keyAuthz = JwsHelper.ComputeKeyAuthorization(signer, challenge.Token);
            return new TlsAlpn01ChallengeValidationDetails
            {
                TokenValue = keyAuthz,
            };
        }
    }
}