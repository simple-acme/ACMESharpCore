using System;
using System.Security.Cryptography;
using System.Text;

namespace ACMESharp.Crypto.JOSE
{
    /// <summary>
    /// A helper class to support JSON Web Signature (JWS) operations as needed for ACME.
    /// </summary>
    /// <remarks>
    /// ACME only requires a subset of JWS functionality, such as only requiring support
    /// for the <see href="https://tools.ietf.org/html/rfc7515#section-7.2.2">Flattened
    /// JWS JSON Serialization</see> format, and so this helper class' scope and
    /// implementation of JWS is limited to those features required for ACME.
    /// </remarks>
    public static partial class JwsHelper
    {
        /*
         *  In the JWS JSON Serialization, a JWS is represented as a JSON object
         *  containing some or all of these four members:
         *    o "protected", with the value BASE64URL(UTF8(JWS Protected Header))
         *    o "header", with the value JWS Unprotected Header
         *    o "payload", with the value BASE64URL(JWS Payload)
         *    o "signature", with the value BASE64URL(JWS Signature)
         *
         *  <!--cSpell:disable-->
         *  Example:
         *    {
         *      "header": {
         *        "alg": "RS256",
         *        "jwk": {
         *          "kty": "RSA",
         *          "n": "xGZV9QR__pWrlw7cPbFaI-84Yn8-qAC3CHUaXmDIqK0kUoXEeZG5P8NmWGf8dCQCAywyc-k5FjP34lEhYwpqn81r_1u1WNVwsAaBfcVEGRy3HwWozWhkXlFXN-HUku_7vrtgR4DM4JzCnHipART-s3Xy6jzmcJSdy-278EsCql7wpNYT9CabxdbtNc7pDIDxt2t69QtVyrjm2NFz6y9AGABR1DksM7YGz-zc-3SdHnotXnKt1m2TXeGIECn7r4LuRbjlnVBTFO77jqbNN5u7kVRQGaqtn4i7AzAHgUtIaZW1iwmlfTE-ek4N6GsK2nO89nHRzmS0YQuqfuNFqGbM0Q",
         *          "e": "AQAB"
         *        }
         *      },
         *      "protected": "eyJub25jZSI6ImJidTdIWmxucGZ0VW95eFZydkdZYkl3ZjVRajdTZkxYVE1pNy1pUGFiUDgifQ",
         *      "payload": "ewogICJyZXNvdXJjZSI6ICJuZXctcmVnIiwKICAiY29udGFjdCI6IFsKICAgICJtYWlsdG86bGV0c2VuY3J5cHRAbWFpbGluYXRvci5jb20iCiAgXQp9",
         *      "signature": "dCK1T9T5Tg1-ZLpJKimHBvvjDNPloJPELvAVyLeRpjxx3sN8GNhqybRONDUz7umXDUaCKSkOX2osZ9GkVJNlda4FLLwn2a_TXHRWXyDyM-LI6ZTOHKW-dSVUR-HUo7MOAA-rdjbEmEOMq00jeLvmepEkElYdRTFEvo42XZHShjY1ybS96iwJbKDetJQCHHYOXrOtKhPC9zKv8FeMgl0ppwzV2YYISEeMZpM70ER0SiI7ECQ3ISn1dpPJBzU-3AEx2lLurkU3PaXbTQ6XoHqr9EmhmjnzsaWAGeL5m_e0JdAbBNcNkNeowGAhSztC5tKDnqn4SFvfgH-e9rDdmDslng"
         *    }
         *  <!--cSpell:enable-->
         *
         * References:
         *   https://tools.ietf.org/html/rfc7515
         *   http://kjur.github.io/jsrsasign/
         *   http://dotnetcodr.com/2014/01/20/introduction-to-oauth2-json-web-tokens/
         */

        /// <summary>
        /// Computes a JSON Web Signature (JWS) according to the rules of RFC 7515 Section 5.
        /// </summary>
        /// <param name="sigFunc"></param>
        /// <param name="payload"></param>
        /// <param name="protectedHeaders"></param>
        /// <returns>Returns a signed, structured object containing the input payload.</returns>
        public static JwsSignedPayload SignFlatJsonAsObject(
            Func<byte[], byte[]> sigFunc,
            string payload,
            string protectedHeaders)
        {
            var payloadB64u = Base64Tool.UrlEncode(Encoding.UTF8.GetBytes(payload));
            var protectedB64u = Base64Tool.UrlEncode(Encoding.UTF8.GetBytes(protectedHeaders ?? ""));

            var signingInput = $"{protectedB64u}.{payloadB64u}";
            var signingBytes = Encoding.ASCII.GetBytes(signingInput);

            var sigBytes = sigFunc(signingBytes);
            var sigB64u = Base64Tool.UrlEncode(sigBytes);

            var jwsFlatJS = new JwsSignedPayload
            {
                Protected = protectedB64u,
                Payload = payloadB64u,
                Signature = sigB64u
            };

            return jwsFlatJS;
        }

        /// <summary>
        /// Computes a thumbprint of the JWK using the argument Hash Algorithm
        /// as per <see href="https://tools.ietf.org/html/rfc7638">RFC 7638</see>,
        /// JSON Web Key (JWK) Thumbprint.
        /// </summary>
        public static byte[] ComputeThumbprint(IJwsTool signer, HashAlgorithm algor)
        {
            // As per RFC 7638 Section 3, we export the JWK in a canonical form
            // and then produce a JSON object with no whitespace or line breaks
            var jwkJson = signer.ExportEab();
            var jwkBytes = Encoding.UTF8.GetBytes(jwkJson);
            var jwkHash = algor.ComputeHash(jwkBytes);

            return jwkHash;
        }

        /// <summary>
        /// Computes the ACME Key AcmeAuthorization of the JSON Web Key (JWK) of an argument
        /// Signer as prescribed in the
        /// <see href="https://tools.ietf.org/html/draft-ietf-acme-acme-01#section-7.1"
        /// >ACME specification, section 7.1</see>.
        /// </summary>
        public static string ComputeKeyAuthorization(IJwsTool signer, string? token)
        {
            using var sha = SHA256.Create();
            var jwkThumb = Base64Tool.UrlEncode(ComputeThumbprint(signer, sha));
            return $"{token}.{jwkThumb}";
        }

        /// <summary>
        /// Computes a SHA256 digest over the <see cref="ComputeKeyAuthorization"
        /// >ACME Key AcmeAuthorization</see> as required by some of the ACME AcmeChallenge
        /// responses.
        /// </summary>
        public static string ComputeKeyAuthorizationDigest(IJwsTool signer, string? token)
        {
            using var sha = SHA256.Create();
            var jwkThumb = Base64Tool.UrlEncode(ComputeThumbprint(signer, sha));
            var keyAuthz = $"{token}.{jwkThumb}";
            var keyAuthzDig = sha.ComputeHash(Encoding.UTF8.GetBytes(keyAuthz));
            return Base64Tool.UrlEncode(keyAuthzDig);
        }
    }
}
