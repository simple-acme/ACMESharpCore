using System;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using static ACMESharp.Crypto.JOSE.Impl.RSJwsTool;

namespace ACMESharp.Crypto.JOSE.Impl
{
    /// <summary>
    /// JWS Signing tool implements RS-family of algorithms as per
    /// http://self-issued.info/docs/draft-ietf-jose-json-web-algorithms-00.html#SigAlgTable
    /// </summary>
    public class RSJwsTool : IJwsTool<RSJwk>
    {
        private HashAlgorithm? _sha;
        private RSACryptoServiceProvider? _rsa;
        private RSJwk? _jwk;

        /// <summary>
        /// Specifies the size in bits of the SHA-2 hash function to use.
        /// Supported values are 256, 384 and 512.
        /// </summary>
        public int HashSize { get; set; } = 256;

        /// <summary>
        /// Specifies the size in bits of the RSA key to use.
        /// Supports values in the range 2048 - 4096 inclusive.
        /// </summary>
        /// <returns></returns>
        public int KeySize { get; set; } = 2048;

        public string JwsAlg => $"RS{HashSize}";

        public void Init()
        {
            _sha = HashSize switch
            {
                256 => SHA256.Create(),
                384 => SHA384.Create(),
                512 => SHA512.Create(),
                _ => throw new InvalidOperationException("illegal SHA2 hash size"),
            };
            if (KeySize < 2048 || KeySize > 4096)
                throw new InvalidOperationException("illegal RSA key bit length");
            _rsa = new RSACryptoServiceProvider(KeySize);
        }

        public void Dispose()
        {
            _rsa?.Dispose();
            _rsa = null;
            _sha?.Dispose();
            _sha = null;
            GC.SuppressFinalize(this);
        }

        public string Export()
        {
            if (_rsa == null)
            {
                throw new InvalidOperationException();
            }
            return _rsa.ToXmlString(true);
        }

        public void Import(string exported)
        {
            if (_rsa == null)
            {
                throw new InvalidOperationException();
            }
            _rsa.FromXmlString(exported);
        }

        public RSJwk ExportJwk()
        {
            // Note, we only produce a canonical form of the JWK
            // for export therefore we ignore the canonical param
            if (_rsa == null)
            {
                throw new InvalidOperationException();
            }
            if (_jwk == null)
            {
                var keyParams = _rsa.ExportParameters(false);
                _jwk = new RSJwk
                {
                    Kty = "RSA",
                    E = Base64Tool.UrlEncode(keyParams.Exponent!),
                    N = Base64Tool.UrlEncode(keyParams.Modulus!),
                };
            }

            return _jwk;
        }

        public string ExportEab()
        {
            return JsonSerializer.Serialize(ExportJwk(), AcmeJson.Insensitive.RSJwk);
        }

        public void ImportJwk(string jwkJson)
        {
            Init();
            var jwk = JsonSerializer.Deserialize(jwkJson, AcmeJson.Insensitive.RSJwk);
            if (jwk == null)
            {
                throw new InvalidOperationException();
            }
            var keyParams = new RSAParameters
            {
                Exponent = Base64Tool.UrlDecode(jwk.E),
                Modulus = Base64Tool.UrlDecode(jwk.N),
            };
            if (_rsa == null)
            {
                throw new InvalidOperationException();
            }
            _rsa.ImportParameters(keyParams);
        }

        public byte[] Sign(byte[] raw)
        {
            if (_rsa == null || _sha == null)
            {
                throw new InvalidOperationException();
            }
            return _rsa.SignData(raw, _sha);
        }

        public bool Verify(byte[] raw, byte[] sig)
        {
            if (_rsa == null || _sha == null)
            {
                throw new InvalidOperationException();
            }
            return _rsa.VerifyData(raw, _sha, sig);
        }

        // As per RFC 7638 Section 3, these are the *required* elements of the
        // JWK and are sorted in lexicographic order to produce a canonical form
        public class RSJwk
        {
            [JsonPropertyOrder(1)]
            [JsonPropertyName("e")]
            public string E { get; set; } = "";

            [JsonPropertyOrder(2)]
            [JsonPropertyName("kty")]
            public string Kty { get; set; } = "";

            [JsonPropertyOrder(3)]
            [JsonPropertyName("n")]
            public string N { get; set; } = "";
        }
    }
}
