using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using System.Threading.Tasks;
using ACMESharp.Crypto;
using ACMESharp.Crypto.JOSE;
using ACMESharp.Protocol.Messages;
using ACMESharp.Protocol.Resources;
using static ACMESharp.Crypto.JOSE.Impl.ESJwsTool;
using static ACMESharp.Crypto.JOSE.Impl.RSJwsTool;
using static ACMESharp.Crypto.JOSE.JwsHelper;
using Authorization = ACMESharp.Protocol.Resources.Authorization;

namespace ACMESharp.Protocol
{
    /// <summary>
    /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7
    /// </summary>
    public class AcmeProtocolClient
    {
        private static readonly HttpStatusCode[] SkipExpectedStatuses = Array.Empty<HttpStatusCode>();
        private readonly HttpClient _http;

        /// <summary>
        /// To implement Let's Encrypt protocol change per RFC 8555,
        /// read announcement here: 
        /// https://community.letsencrypt.org/t/acme-v2-scheduled-deprecation-of-unauthenticated-resource-gets/74380
        /// </summary>
        private readonly bool _usePostAsGet;

        public AcmeProtocolClient(HttpClient http, bool usePostAsGet = false)
        {
            _http = http;
            if (http.BaseAddress == null)
            {
                throw new ArgumentException("http lacks BaseAddress");
            }
            Directory = new ServiceDirectory();
            Signer = ResolveDefaultSigner();
            _usePostAsGet = usePostAsGet;
        }

        private static IJwsTool ResolveDefaultSigner()
        {
            // We default to ES256 signer
            var signer = new Crypto.JOSE.Impl.ESJwsTool();
            signer.Init();
            return signer;
        }

        /// <summary>
        /// A tool that can be used to JWS-sign request messages to the
        /// target ACME server.
        /// </summary>
        /// <remarks>
        /// If not specified during construction, a default signing tool
        /// with a new set of keys will be constructed of type ES256
        /// (Elliptic Curve using the P-256 curve and a SHA256 hash).
        /// </remarks>
        public IJwsTool Signer { get; private set; }

        public ServiceDirectory Directory { get; set; }

        public AccountDetails? Account { get; set; }

        public string? NextNonce { get; private set; }

        /// <summary>
        /// Retrieves the Directory object from the target ACME CA.  The Directory is used
        /// to help clients configure themselves with the right URLs for each ACME operation.
        /// </summary>
        /// <remarks>
        /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.1.1
        /// </remarks>
        public async Task<ServiceDirectory?> GetDirectoryAsync(string relativeUri)
        {
            var ret = await SendAcmeAsync(new Uri(_http.BaseAddress!, relativeUri ?? ""), AcmeJson.Insensitive.ServiceDirectory, skipNonce: true);
            return ret.Value;
        }

        /// <summary>
        /// Convenience routine to retrieve the raw bytes of the Terms of Service
        /// endpoint defined in an ACME Resource Directory meta details.
        /// </summary>
        /// <returns>Returns a tuple containing the content type, the filename as best
        ///         can be determined by the response headers or the request URL, and
        ///         the raw content bytes; typically this might resolve to a PDF file</returns>
        public async Task<(MediaTypeHeaderValue? contentType, string? filename, byte[]? content)> GetTermsOfServiceAsync()
        {
            var tosUrl = Directory?.Meta?.TermsOfService;
            if (tosUrl == null)
            {
                return (null, null, null);
            }

            try
            {
                using var resp = await _http.GetAsync(tosUrl);
                var filename = resp.Content?.Headers?.ContentDisposition?.FileName;
                if (string.IsNullOrEmpty(filename))
                {
                    filename = new Uri(tosUrl).AbsolutePath;
                }
                if (resp.Content != null)
                {
                    return (
                        resp.Content.Headers.ContentType,
                        Path.GetFileName(filename),
                        await resp.Content.ReadAsByteArrayAsync()
                    );
                }
                else
                {
                    return (null, null, null);
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Error retrieving terms of service from {tosUrl}", ex);
            }
        }

        /// <summary>
        /// Retrieves a fresh nonce to be used in subsequent communication
        /// between the client and target ACME CA.  The client might
        /// sometimes need to get a new nonce, e.g., on its first request
        /// to the server or if an existing nonce is no longer valid.
        /// </summary>
        /// <remarks>
        /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.2
        /// </remarks>
        public async Task GetNonceAsync()
        {
            // Some weird behavior here:
            // According to RFC, this should respond to HEAD request with 200
            // and to GET request with a 204, but we're seeing 204 for both
            if (Directory.NewNonce == null)
            {
                throw new InvalidOperationException();
            }
            _ = await SendAcmeAsync(
                    new Uri(Directory.NewNonce),
                    method: HttpMethod.Head,
                    expectedStatuses: new[] {
                        HttpStatusCode.OK,
                        HttpStatusCode.NoContent,
                    });
        }

        /// <summary>
        /// </summary>
        /// <remarks>
        /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.3
        /// </remarks>
        public async Task<AccountDetails> CreateAccountAsync(
            IEnumerable<string>? contacts = null,
            bool termsOfServiceAgreed = false,
            JwsSignedPayload? externalAccountBinding = null)
        {
            var message = new CreateAccountRequest
            {
                Contact = contacts,
                TermsOfServiceAgreed = termsOfServiceAgreed,
                ExternalAccountBinding = externalAccountBinding,
            };
            var resp = await SendAcmeAsync(
                new Uri(_http.BaseAddress!, Directory.NewAccount),
                AcmeJson.Default.CreateAccountRequest,
                AcmeJson.Default.Account,
                method: HttpMethod.Post,
                message: message,
                expectedStatuses: new[] { HttpStatusCode.Created, HttpStatusCode.OK },
                includePublicKey: true);

            return DecodeAccountResponse(resp);
        }

        /// <summary>
        /// Verifies that an Account exists in the target ACME CA that is associated
        /// associated with the current Account Public Key.  If the check succeeds,
        /// the returned Account  object will <b>only</b> have its <c>Kid</c>
        /// property populated -- all other fields will be empty.
        /// </summary>
        /// <remarks>
        /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.3.1
        /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.3.3
        /// <para>
        /// If the Account does not exist, then an exception is thrown.
        /// </para>
        /// </remarks>
        public async Task<AccountDetails> CheckAccountAsync()
        {
            var resp = await SendAcmeAsync(
                    new Uri(_http.BaseAddress!, Directory.NewAccount),
                    requestType: AcmeJson.Default.CheckAccountRequest,
                    responseType: AcmeJson.Default.Account,
                    method: HttpMethod.Post,
                    message: new CheckAccountRequest(),
                    expectedStatuses: SkipExpectedStatuses,
                    includePublicKey: true);

            if (resp.Message.StatusCode == HttpStatusCode.BadRequest)
                throw new InvalidOperationException($"Invalid or missing account ({resp.Message.StatusCode})");

            if (resp.Message.StatusCode != HttpStatusCode.OK)
                throw await DecodeResponseErrorAsync(resp.Message);

            return DecodeAccountResponse(resp, existing: Account);
        }

        /// <summary>
        /// Updates existing Account information registered with the ACME CA.
        /// </summary>
        /// <remarks>
        /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.3.2
        /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.3.3
        /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.3.4
        /// </remarks>
        public async Task<AccountDetails> UpdateAccountAsync(IEnumerable<string>? contacts = null)
        {
            if (Account == null)
            {
                throw new InvalidOperationException();
            }
            var requUrl = new Uri(_http.BaseAddress!, Account.Value.Kid);
            var message = new UpdateAccountRequest
            {
                Contact = contacts
            };
            var resp = await SendAcmeAsync(
                    requUrl,
                    requestType: AcmeJson.Default.UpdateAccountRequest,
                    responseType: AcmeJson.Default.Account,
                    method: HttpMethod.Post,
                    message: message);

            return DecodeAccountResponse(resp, existing: Account);
        }

        // TODO: handle "Change of TOS" error response
        //    https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.3.4


        /// <summary>
        /// Rotates the current Public key that is associated with this Account by the
        /// target ACME CA with a new Public key.  If successful, updates the current
        /// Account key pair registered with the client.
        /// </summary>
        /// <remarks>
        /// https://tools.ietf.org/html/draft-ietf-acme-acme-18#section-7.3.5
        /// </remarks>
        public async Task<AccountDetails?> ChangeAccountKeyAsync(IJwsTool newSigner)
        {
            if (Account == null)
            {
                Signer = newSigner;
                return null;
            }

            var requUrl = new Uri(_http.BaseAddress!, Directory.KeyChange);
            string? innerPayload;
            if (Signer is IJwsTool<RSJwk> rsa)
            {
                var req = new KeyChangeRequest<RSJwk>()
                {
                    Account = Account.Value.Kid,
                    OldKey = rsa.ExportJwk(),
                };
                innerPayload = ComputeAcmeSigned(req, AcmeJson.Default.KeyChangeRequestRSJwk, requUrl.ToString(), signer: newSigner, includePublicKey: true, excludeNonce: true);
            }
            else if (Signer is IJwsTool<ESJwk> ec)
            {
                var req = new KeyChangeRequest<ESJwk>()
                {
                    Account = Account.Value.Kid,
                    OldKey = ec.ExportJwk(),
                };
                innerPayload = ComputeAcmeSigned(req, AcmeJson.Default.KeyChangeRequestESJwk, requUrl.ToString(), signer: newSigner, includePublicKey: true, excludeNonce: true);
            }
            else
            {
                throw new NotImplementedException();
            }

            var resp = await SendAcmeAsync(
                    requUrl,
                    AcmeJson.Default.Account,
                    method: HttpMethod.Post,
                    message: innerPayload);

            Signer = newSigner;

            return DecodeAccountResponse(resp, existing: Account);
        }

        /// <summary>
        /// Creates a new Order for a Certificate which will contain one or more
        /// DNS Identifiers.  The first Identifier will be treated as the primary
        /// subject of the certificate, and any optional subsequent Identifiers
        /// will be treated as Subject Alterative Name (SAN) entries.
        /// </summary>
        /// <remarks>
        /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.4
        /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.1.3
        /// </remarks>
        public async Task<OrderDetails> CreateOrderAsync(IEnumerable<Identifier> identifiers, DateTime? notBefore = null, DateTime? notAfter = null)
        {
            var message = new CreateOrderRequest
            {
                Identifiers = identifiers.ToArray(),
                NotBefore = notBefore?.ToString(Constants.Rfc3339DateTimeFormat),
                NotAfter = notAfter?.ToString(Constants.Rfc3339DateTimeFormat),
            };
            var resp = await SendAcmeAsync(
                    new Uri(_http.BaseAddress!, Directory.NewOrder),
                    requestType: AcmeJson.Insensitive.CreateOrderRequest,
                    responseType: AcmeJson.Insensitive.Order,
                    method: HttpMethod.Post,
                    message: message,
                    expectedStatuses: new[] { HttpStatusCode.Created, HttpStatusCode.OK });

            return DecodeOrderResponse(resp);
        }

        /// <summary>
        /// Retrieves the current status and details of an existing Order.
        /// </summary>
        /// <remarks>
        /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.4
        /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.1.3
        /// <para>
        /// You can optionally pass in an existing Order details object if this
        /// is refreshing the state of an existing one, and some values that
        /// don't change, but also are not supplied in subsequent requests, such
        /// as the Order URL, will be copied over.
        /// </para>
        /// </remarks>
        public async Task<OrderDetails> GetOrderDetailsAsync(string orderUrl, OrderDetails? existing = null)
        {
            var method = _usePostAsGet ? HttpMethod.Post : HttpMethod.Get;
            var message = _usePostAsGet ? "" : null;
            var skipNonce = !_usePostAsGet;
            var resp = await SendAcmeAsync(
                    new Uri(_http.BaseAddress!, orderUrl),
                    responseType: AcmeJson.Insensitive.Order,
                    method: method,
                    message: message,
                    skipNonce: skipNonce);
            return DecodeOrderResponse(resp, existing);
        }

        /// <summary>
        /// Retrieves the details of an Authorization associated with a previously
        /// created Order.  The Authorization details URL is returned as part of
        /// an Order's response.
        /// </summary>
        /// <remarks>
        /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.5
        /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.1.4
        /// <para>
        /// Use this operation to retrieve the initial details of an Authorization,
        /// such as immediately after creating a new Order, as well as to retrieve
        /// the subsequent state and progress of an Authorization, such as as after
        /// responding to an associated Challenge.
        /// </para>
        /// </remarks>
        public async Task<Authorization> GetAuthorizationDetailsAsync(string authzDetailsUrl)
        {
            var method = _usePostAsGet ? HttpMethod.Post : HttpMethod.Get;
            var message = _usePostAsGet ? "" : null;
            var skipNonce = !_usePostAsGet;
            var typedResp = await SendAcmeAsync(
                    new Uri(_http.BaseAddress!, authzDetailsUrl),
                    AcmeJson.Insensitive.Authorization,
                    method: method,
                    message: message,
                    skipNonce: skipNonce);
            return typedResp.Value;
        }

        /// <summary>
        /// Deactivates a specific Authorization and thereby relinquishes the
        /// authority to issue Certificates for the associated Identifier.
        /// </summary>
        /// <remarks>
        /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.5.2
        /// </remarks>
        public async Task<Authorization> DeactivateAuthorizationAsync(string authzDetailsUrl)
        {
            var typedResp = await SendAcmeAsync(
                    new Uri(_http.BaseAddress!, authzDetailsUrl),
                    responseType: AcmeJson.Insensitive.Authorization,
                    requestType: AcmeJson.Insensitive.DeactivateAuthorizationRequest,
                    method: HttpMethod.Post,
                    message: new DeactivateAuthorizationRequest());
            return typedResp.Value;
        }

        /// <summary>
        /// </summary>
        /// <remarks>
        /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.5.1
        /// </remarks>
        public async Task<Challenge> GetChallengeDetailsAsync(string challengeDetailsUrl)
        {
            var method = _usePostAsGet ? HttpMethod.Post : HttpMethod.Get;
            var message = _usePostAsGet ? "" : null;
            var skipNonce = !_usePostAsGet;
            var typedResp = await SendAcmeAsync(
                    new Uri(_http.BaseAddress!, challengeDetailsUrl),
                    AcmeJson.Insensitive.Challenge,
                    method: method,
                    message: message,
                    skipNonce: skipNonce);

            return typedResp.Value;
        }

        /// <summary>
        /// </summary>
        /// <remarks>
        /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.5.1
        /// </remarks>
        public async Task<Challenge> AnswerChallengeAsync(string challengeDetailsUrl)
        {
            var typedResp = await SendAcmeAsync(
                    new Uri(_http.BaseAddress!, challengeDetailsUrl),
                    AcmeJson.Insensitive.Challenge,
                    method: HttpMethod.Post);
            return typedResp.Value;
        }

        /// <summary>
        /// </summary>
        /// <remarks>
        /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.4
        /// </remarks>
        public async Task<OrderDetails> FinalizeOrderAsync(string orderFinalizeUrl, byte[] derEncodedCsr)
        {
            var message = new FinalizeOrderRequest
            {
                Csr = Base64Tool.UrlEncode(derEncodedCsr),
            };
            var resp = await SendAcmeAsync(
                    new Uri(_http.BaseAddress!, orderFinalizeUrl),
                    requestType: AcmeJson.Insensitive.FinalizeOrderRequest,
                    responseType: AcmeJson.Insensitive.Order,
                    expectedStatuses: new[] { HttpStatusCode.OK, HttpStatusCode.Created },
                    method: HttpMethod.Post,
                    message: message);

            return DecodeOrderResponse(resp);
        }

        /// <summary>
        /// Get ACME certificate including metadata
        /// </summary>
        /// <param name="order"></param>
        /// <returns></returns>
        public async Task<AcmeCertificate> GetOrderCertificateExAsync(OrderDetails order)
        {
            using var resp = await GetAsync(order.Payload.Certificate);
            var ret = new AcmeCertificate();
            if (resp.Headers.TryGetValues("Link", out var linkValues))
            {
                ret.Links = new HTTP.LinkCollection(linkValues);
            }
            ret.Certificate = await resp.Content.ReadAsByteArrayAsync();
            return ret;
        }

        /// <summary>
        /// Revoke certificate
        /// </summary>
        /// <remarks>
        /// https://tools.ietf.org/html/draft-ietf-acme-acme-18#section-7.6
        /// </remarks>
        public async Task<bool> RevokeCertificateAsync(byte[] derEncodedCertificate, RevokeReason reason = RevokeReason.Unspecified)
        {
            var message = new RevokeCertificateRequest
            {
                Certificate = Base64Tool.UrlEncode(derEncodedCertificate),
                Reason = reason
            };
            // If OK is returned, we're all done. Otherwise general 
            // exception handling will kick in
            _ = await SendAcmeAsync(
                    new Uri(_http.BaseAddress!, Directory.RevokeCert),
                    requestType: AcmeJson.Insensitive.RevokeCertificateRequest,
                    responseType: AcmeJson.Insensitive.Object,
                    method: HttpMethod.Post,
                    message: message,
                    expectedStatuses: new[] { HttpStatusCode.OK });
            return true;
        }

        /// <summary>
        /// Generic fetch routine to retrieve raw bytes from a URL associated
        /// with an ACME endpoint.
        /// </summary>
        /// <param name="relativeUrl">The URL to fetch which may be relative to the ACME
        ///         endpoint associated with this client instance</param>
        /// <returns>A tuple containing the content type and the raw content bytes</returns>
        public async Task<HttpResponseMessage> GetAsync(string relativeUrl)
        {
            var url = new Uri(_http.BaseAddress!, relativeUrl);
            var method = _usePostAsGet ? HttpMethod.Post : HttpMethod.Get;
            var message = _usePostAsGet ? "" : null;
            var skipNonce = !_usePostAsGet;
            var resp = await SendAcmeAsync(url, method, message, skipNonce: skipNonce);
            _ = resp.EnsureSuccessStatusCode();
            return resp;
        }

        /// <summary>
        /// The workhorse routine for submitting HTTP requests using ACME protocol
        /// semantics and activating pre- and post-submission event hooks.
        /// </summary>
        /// <param name="uri">URI to send to</param>
        /// <param name="method">HTTP Method to use, defaults to <c>GET</c></param>
        /// <param name="message">Optional request payload, will be JSON-serialized</param>
        /// <param name="expectedStatuses">Any HTTP response statuses that can be interpretted
        ///         as successful, defaults to <c>OK (200)</c>; other response statuses will
        ///         trigger an exception; you can also skip response status checking by supplying
        ///         a zero-length array value here</param>
        /// <param name="skipNonce">If true, will not expect and extract a Nonce header in the
        ///         response, defaults to <c>false</c></param>
        /// <param name="opName">Name of operation, will be auto-populated with calling method
        ///         name if unspecified</param>
        /// <returns>The returned HTTP response message, unaltered, after inspecting the
        ///         response details for possible error or problem result</returns>
        async Task<HttpResponseMessage> SendAcmeAsync(
            Uri uri,
            HttpMethod? method = null,
            string? message = null,
            HttpStatusCode[]? expectedStatuses = null,
            bool skipNonce = false,
            [System.Runtime.CompilerServices.CallerMemberName] string opName = "")
        {
            if (method == null)
                method = HttpMethod.Get;
            expectedStatuses ??= new[] { HttpStatusCode.OK };

            var requ = new HttpRequestMessage(method, uri);
            if (message != null)
            {
                requ.Content = new StringContent(message);
                requ.Content.Headers.ContentType = Constants.JsonContentTypeHeaderValue;
            }

            var resp = await _http.SendAsync(requ);
            if (expectedStatuses.Length > 0 && !expectedStatuses.Contains(resp.StatusCode))
            {
                // Since we're about to throw anyway, we process a nonce if it's
                // there but if not we don't want to overshadow the more immediate
                // error that we're about to signal with an exception
                if (!skipNonce)
                    _ = ExtractNextNonce(resp, true);

                throw await DecodeResponseErrorAsync(resp, opName: opName);
            }

            if (!skipNonce)
                _ = ExtractNextNonce(resp);

            return resp;
        }

        /// <summary>
        /// Send request with body
        /// </summary>
        /// <typeparam name="TResponse"></typeparam>
        /// <typeparam name="TRequest"></typeparam>
        /// <param name="uri"></param>
        /// <param name="requestType"></param>
        /// <param name="responseType"></param>
        /// <param name="method"></param>
        /// <param name="message"></param>
        /// <param name="expectedStatuses"></param>
        /// <param name="skipNonce"></param>
        /// <param name="skipSigning"></param>
        /// <param name="includePublicKey"></param>
        /// <param name="opName"></param>
        /// <returns></returns>
        async Task<Response<TResponse>> SendAcmeAsync<TResponse, TRequest>(
            Uri uri, JsonTypeInfo<TRequest> requestType, JsonTypeInfo<TResponse> responseType,
            HttpMethod? method = null, TRequest? message = null, HttpStatusCode[]? expectedStatuses = null,
            bool skipNonce = false, bool skipSigning = false, bool includePublicKey = false,
            [System.Runtime.CompilerServices.CallerMemberName] string opName = "")
            where TRequest : class
        {
            string? payload = null;
            if (message != null)
            {
                payload = skipSigning
                    ? JsonSerializer.Serialize(message, requestType)
                    : ComputeAcmeSigned(message, requestType, uri.ToString(), includePublicKey: includePublicKey);
            }

            var response = await SendAcmeAsync(uri, method, payload, expectedStatuses, skipNonce, opName);
            return new Response<TResponse>()
            {
                Message = response,
                Value = await Deserialize(response, responseType)
            };
        }

        public record struct Response<TResponse>
        {
            public HttpResponseMessage Message { get; set; }
            public TResponse? Value { get; set; }
        }

        /// <summary>
        /// Send request without body
        /// </summary>
        /// <typeparam name="TResponse"></typeparam>
        /// <param name="uri"></param>
        /// <param name="responseType"></param>
        /// <param name="message"></param>
        /// <param name="method"></param>
        /// <param name="expectedStatuses"></param>
        /// <param name="skipNonce"></param>
        /// <param name="opName"></param>
        /// <returns></returns>
        async Task<Response<TResponse>> SendAcmeAsync<TResponse>(
            Uri uri, JsonTypeInfo<TResponse> responseType,
            string? message = null,
            HttpMethod? method = null, HttpStatusCode[]? expectedStatuses = null,
            bool skipNonce = false,
            [System.Runtime.CompilerServices.CallerMemberName] string opName = "")
        {
            var response = await SendAcmeAsync(uri, method, message, expectedStatuses, skipNonce, opName);
            return new Response<TResponse>()
            {
                Message = response,
                Value = await Deserialize(response, responseType)
            };
        }

        static async Task<T?> Deserialize<T>(HttpResponseMessage resp, JsonTypeInfo<T> typeInfo)
        {
            var content = await resp.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize(content, typeInfo);
        }

        static async Task<AcmeProtocolException> DecodeResponseErrorAsync(HttpResponseMessage resp,
            string? message = null,
            [System.Runtime.CompilerServices.CallerMemberName] string opName = "")
        {
            string? msg = null;
            Problem? problem = null;

            // if (Constants.ProblemContentTypeHeaderValue.Equals(resp.Content?.Headers?.ContentType))
            if (Constants.ProblemContentTypeHeaderValue.Equals(resp.Content?.Headers?.ContentType))
            {
                problem = await Deserialize(resp, AcmeJson.Insensitive.Problem);
                msg = problem?.Detail;
            }

            if (string.IsNullOrEmpty(msg))
            {
                msg = $"Unexpected response status code [{resp.StatusCode}] for [{opName}]";
            }
            return new AcmeProtocolException(resp, message ?? msg, problem);
        }

        /// <summary>
        /// Decodes an HTTP response, including the JSON payload and the ancillary HTTP data,
        /// into Account details.
        /// </summary>
        /// <param name="resp"></param>
        /// <param name="existing">Optionally, provide a previously decoded Account object
        ///         whose elements will be re-used as necessary to populate the new result
        ///         Account object; some ACME Account operations do not return the full
        ///         details of an existing Account</param>
        /// <returns></returns>
        protected static AccountDetails DecodeAccountResponse(Response<Account> resp, AccountDetails? existing = null)
        {
            if (!resp.Message.Headers.TryGetValues("Link", out var linkValues))
            {
                throw new InvalidDataException();
            }
            var acctUrl = resp.Message.Headers.Location?.ToString();
            var links = new HTTP.LinkCollection(linkValues); // This allows/handles null
            var tosLink = links.GetFirstOrDefault(Constants.TosLinkHeaderRelationKey)?.Uri;
            if (resp.Value == default)
            {
                throw new InvalidDataException();
            }
            var acct = new AccountDetails
            {
                Payload = resp.Value,
                Kid = acctUrl ?? existing?.Kid ?? throw new InvalidDataException("Missing KID"),
                TosLink = tosLink ?? existing?.TosLink
            };
            return acct;
        }

        protected static OrderDetails DecodeOrderResponse(Response<Order> resp, OrderDetails? existing = null)
        {
            var orderUrl = resp.Message.Headers.Location?.ToString();
            var order = new OrderDetails
            {
                Payload = resp.Value,
                OrderUrl = orderUrl ?? existing?.OrderUrl ?? throw new InvalidOperationException("missing orderUrl"),
            };
            return order;
        }

        protected bool ExtractNextNonce(HttpResponseMessage resp, bool skipThrow = false)
        {
            var headerName = Constants.ReplayNonceHeaderName;
            NextNonce = null;
            if (resp.Headers.TryGetValues(headerName, out var values))
            {
                NextNonce = string.Join(",", values);
                return true;
            }
            else if (!skipThrow)
            {
                throw new Exception($"missing header:  {headerName}");
            }
            return false;
        }

        /// <summary>
        /// Computes the JWS-signed ACME request body for the given message object
        /// and the current or input <see cref="Signer"/>.
        /// </summary>
        protected string ComputeAcmeSigned<T>(T message, JsonTypeInfo<T> typeInfo, string requUrl,
            IJwsTool? signer = null,
            bool includePublicKey = false,
            bool excludeNonce = false)
        {
            signer ??= Signer;
            var protectedHeaderSer = "";
            if (signer is IJwsTool<RSJwk> rs)
            {
                var protectedHeader = CreateProtectedHeader(rs, requUrl, includePublicKey, excludeNonce);
                protectedHeaderSer = JsonSerializer.Serialize(protectedHeader, AcmeJson.Insensitive.ProtectedHeaderRSJwk);
            }
            else if (signer is IJwsTool<ESJwk> es)
            {
                var protectedHeader = CreateProtectedHeader(es, requUrl, includePublicKey, excludeNonce);
                protectedHeaderSer = JsonSerializer.Serialize(protectedHeader, AcmeJson.Insensitive.ProtectedHeaderESJwk);
            }
            var payload = JsonSerializer.Serialize(message, typeInfo);
            var jwsFlatJS = SignFlatJsonAsObject(signer.Sign, payload, protectedHeaderSer);
            return JsonSerializer.Serialize(jwsFlatJS, AcmeJson.Insensitive.JwsSignedPayload);
        }

        protected ProtectedHeader<T> CreateProtectedHeader<T>(IJwsTool<T> signer, string url, bool includePublicKey, bool excludeNonce) 
        {
            var protectedHeader = new ProtectedHeader<T>()
            {
                Algorithm = signer.JwsAlg,
                Url = url
            };
            if (includePublicKey)
            {
                protectedHeader.Key = signer.ExportJwk();
            }
            else
            {
                protectedHeader.KeyIdentifier = Account?.Kid ?? throw new InvalidOperationException();
            }
            if (!excludeNonce)
            {
                if (string.IsNullOrEmpty(NextNonce))
                    throw new Exception("missing next nonce needed to sign request payload");
                protectedHeader.Nonce = NextNonce;
            }
            return protectedHeader;
        }
    }
}
