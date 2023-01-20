using System;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using static ACMESharp.Crypto.JOSE.Impl.ESJwsTool;

namespace ACMESharp.Crypto.JOSE.Impl
{
    /// <summary>
    /// JWS Signing tool implements ES-family of algorithms as per
    /// http://self-issued.info/docs/draft-ietf-jose-json-web-algorithms-00.html#SigAlgTable
    /// </summary>
    public class ESJwsTool : IJwsTool<ESJwk>
    {
        private HashAlgorithmName _shaName;
        private ECDsa? _dsa;
        private ESJwk? _jwk;

        /// <summary>
        /// Specifies the size in bits of the SHA-2 hash function to use.
        /// Supported values are 256, 384 and 512.
        /// </summary>
        public int HashSize { get; set; } = 256;

        /// <summary>
        /// Specifies the elliptic curve to use.
        /// </summary>
        /// <returns></returns>
        public ECCurve Curve { get; private set; } = ECCurve.NamedCurves.nistP256;

        /// <summary>
        /// As per:  https://tools.ietf.org/html/rfc7518#section-6.2.1.1
        /// </summary>
        public string CurveName { get; private set; } = "P-256";

        public string JwsAlg => $"ES{HashSize}";

        public void Init()
        {
            switch (HashSize)
            {
                case 256:
                    _shaName = HashAlgorithmName.SHA256;
                    Curve = ECCurve.NamedCurves.nistP256;
                    CurveName = "P-256";
                    break;
                case 384:
                    _shaName = HashAlgorithmName.SHA384;
                    Curve = ECCurve.NamedCurves.nistP384;
                    CurveName = "P-384";
                    break;
                case 512:
                    _shaName = HashAlgorithmName.SHA512;
                    Curve = ECCurve.NamedCurves.nistP521;
                    CurveName = "P-521";
                    break;
                default:
                    throw new InvalidOperationException("illegal SHA2 hash size");
            }
            _dsa = ECDsa.Create(Curve);
        }

        public void Dispose()
        {
            _dsa?.Dispose();
            _dsa = null;
            GC.SuppressFinalize(this);
        }

        public string Export()
        {
            if (_dsa == null)
            {
                throw new InvalidOperationException();
            }
            var ecParams = _dsa.ExportParameters(true);
            var details = new ESPrivateExport
            {
                HashSize = HashSize,
                D = Convert.ToBase64String(ecParams.D!),
                X = Convert.ToBase64String(ecParams.Q!.X!),
                Y = Convert.ToBase64String(ecParams.Q!.Y!),
            };
            return JsonSerializer.Serialize(details, AcmeJson.Insensitive.ESPrivateExport);
        }

        public void Import(string exported)
        {
            // TODO: this is inefficient and corner cases exist that will break this -- FIX THIS!!!
            if (_dsa == null)
            {
                throw new InvalidOperationException();
            }
            var details = JsonSerializer.Deserialize(exported, AcmeJson.Insensitive.ESPrivateExport);
            if (details == null)
            {
                throw new InvalidOperationException();
            }
            HashSize = details.HashSize;
            Init();

            var ecParams = _dsa.ExportParameters(true);
            ecParams.D = Convert.FromBase64String(details.D);
            ecParams.Q.X = Convert.FromBase64String(details.X);
            ecParams.Q.Y = Convert.FromBase64String(details.Y);
            _dsa.ImportParameters(ecParams);

        }

        public ESJwk ExportJwk()
        {
            // Note, we only produce a canonical form of the JWK
            // for export therefore we ignore the canonical param
            if (_dsa == null)
            {
                throw new InvalidOperationException();
            }
            if (_jwk == null)
            {
                var keyParams = _dsa.ExportParameters(false);
                _jwk = new ESJwk
                {
                    Kty = "EC",
                    Crv = CurveName,
                    X = Base64Tool.UrlEncode(keyParams.Q!.X!),
                    Y = Base64Tool.UrlEncode(keyParams.Q!.Y!),
                };
            }
            return _jwk;
        }

        public string ExportEab()
        {
            return JsonSerializer.Serialize(ExportJwk(), AcmeJson.Insensitive.ESJwk);
        }

        public byte[] Sign(byte[] raw)
        {
            if (_dsa == null)
            {
                throw new InvalidOperationException();
            }
            return _dsa.SignData(raw, _shaName);
        }

        public bool Verify(byte[] raw, byte[] sig)
        {
            if (_dsa == null)
            {
                throw new InvalidOperationException();
            }
            return _dsa.VerifyData(raw, sig, _shaName);
        }

        /// <summary>
        /// Format for an internal representation of string-based export/import.
        /// </summary>
        public class ESPrivateExport
        {
            public int HashSize { get; set; }

            public string D { get; set; } = "";

            public string X { get; set; } = "";

            public string Y { get; set; } = "";
        }

        // As per RFC 7638 Section 3, these are the *required* elements of the
        // JWK and are sorted in lexicographic order to produce a canonical form
        public record class ESJwk
        {
            [JsonPropertyOrder(1)]
            [JsonPropertyName("crv")]
            public string Crv { get; set; } = "";

            [JsonPropertyOrder(2)]
            [JsonPropertyName("kty")]
            public string Kty { get; set; } = "";

            [JsonPropertyOrder(3)]
            [JsonPropertyName("x")]
            public string X { get; set; } = "";

            [JsonPropertyOrder(4)]
            [JsonPropertyName("y")]
            public string Y { get; set; } = "";
        }
    }
}