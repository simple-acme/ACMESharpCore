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
using AcmeAuthorization = ACMESharp.Protocol.Resources.AcmeAuthorization;

namespace ACMESharp.Protocol
{
    /// <summary>
    /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7
    /// </summary>
    public class AcmeProtocolClient
    {
        private static readonly HttpStatusCode[] SkipExpectedStatuses = [];
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
            Signer = ResolveDefaultSigner;
            _usePostAsGet = usePostAsGet;
        }

        private static IJwsTool ResolveDefaultSigner
        {
            get
            {
                // We default to ES256 signer
                var signer = new Crypto.JOSE.Impl.ESJwsTool();
                signer.Init();
                return signer;
            }
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
        public IJwsTool Signer { get; set; }

        public ServiceDirectory Directory { get; set; }

        public AccountDetails? Account { get; set; }

        public string? NextNonce { get; set; }

        /// <summary>
        /// Retrieves the Directory object from the target ACME CA.  The Directory is used
        /// to help clients configure themselves with the right URLs for each ACME operation.
        /// </summary>
        /// <remarks>
        /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.1.1
        /// </remarks>
        public async Task<ServiceDirectory?> GetDirectoryAsync(string relativeUri)
        {
            var ret = await SendAcmeAsync(relativeUri, AcmeJson.Insensitive.ServiceDirectory, method: HttpMethod.Get);
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
                    Directory.NewNonce,
                    method: HttpMethod.Head,
                    expectedStatuses: [
                        HttpStatusCode.OK,
                        HttpStatusCode.NoContent,
                    ]);
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
            if (string.IsNullOrWhiteSpace(Directory.NewAccount))
            {
                throw new NotSupportedException();
            }
            var message = new CreateAccountRequest
            {
                Contact = contacts,
                TermsOfServiceAgreed = termsOfServiceAgreed,
                ExternalAccountBinding = externalAccountBinding,
            };
            var resp = await SendAcmeAsync(
                Directory.NewAccount,
                AcmeJson.Insensitive.CreateAccountRequest,
                AcmeJson.Insensitive.Account,
                message: message,
                expectedStatuses: [HttpStatusCode.Created, HttpStatusCode.OK],
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
            if (string.IsNullOrWhiteSpace(Directory.NewAccount))
            {
                throw new NotSupportedException();
            }
            var resp = await SendAcmeAsync(
                    Directory.NewAccount,
                    requestType: AcmeJson.Insensitive.CheckAccountRequest,
                    responseType: AcmeJson.Insensitive.Account,
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
            var message = new UpdateAccountRequest
            {
                Contact = contacts
            };
            var resp = await SendAcmeAsync(
                    Account.Value.Kid,
                    requestType: AcmeJson.Insensitive.UpdateAccountRequest,
                    responseType: AcmeJson.Insensitive.Account,
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
            if (string.IsNullOrWhiteSpace(Directory.KeyChange))
            {
                throw new NotSupportedException();
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
                var serialized = JsonSerializer.Serialize(req, AcmeJson.Insensitive.KeyChangeRequestRSJwk);
                innerPayload = ComputeAcmeSigned(serialized, requUrl.ToString(), signer: newSigner, includePublicKey: true, excludeNonce: true);
            }
            else if (Signer is IJwsTool<ESJwk> ec)
            {
                var req = new KeyChangeRequest<ESJwk>()
                {
                    Account = Account.Value.Kid,
                    OldKey = ec.ExportJwk(),
                };
                var serialized = JsonSerializer.Serialize(req, AcmeJson.Insensitive.KeyChangeRequestESJwk);
                innerPayload = ComputeAcmeSigned(serialized, requUrl.ToString(), signer: newSigner, includePublicKey: true, excludeNonce: true);
            }
            else
            {
                throw new NotImplementedException();
            }

            var resp = await SendAcmeAsync(
                    Directory.KeyChange,
                    AcmeJson.Insensitive.Account,
                    message: innerPayload);

            Signer = newSigner;

            return DecodeAccountResponse(resp, existing: Account);
        }

        /// <summary>
        /// Creates a new AcmeOrder for a Certificate which will contain one or more
        /// DNS Identifiers.  The first AcmeIdentifier will be treated as the primary
        /// subject of the certificate, and any optional subsequent Identifiers
        /// will be treated as Subject Alterative Name (SAN) entries.
        /// </summary>
        /// <remarks>
        /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.4
        /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.1.3
        /// </remarks>
        public async Task<AcmeOrderDetails> CreateOrderAsync(IEnumerable<AcmeIdentifier> identifiers, string? replaces = null, DateTime? notBefore = null, DateTime? notAfter = null)
        {
            if (string.IsNullOrEmpty(Directory.NewOrder))
            {
                throw new NotSupportedException();
            }
            var message = new CreateOrderRequest
            {
                Identifiers = identifiers.ToArray(),
                Replaces = replaces,
                NotBefore = notBefore?.ToString(Constants.Rfc3339DateTimeFormat),
                NotAfter = notAfter?.ToString(Constants.Rfc3339DateTimeFormat),
            };
            var resp = await SendAcmeAsync(
                Directory.NewOrder,
                requestType: AcmeJson.Insensitive.CreateOrderRequest,
                responseType: AcmeJson.Insensitive.AcmeOrder,
                message: message,
                expectedStatuses: [HttpStatusCode.Created, HttpStatusCode.OK]);

            return DecodeOrderResponse(resp);
        }

        /// <summary>
        /// Retrieves the current status and details of an existing AcmeOrder.
        /// </summary>
        /// <remarks>
        /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.4
        /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.1.3
        /// <para>
        /// You can optionally pass in an existing AcmeOrder details object if this
        /// is refreshing the state of an existing one, and some values that
        /// don't change, but also are not supplied in subsequent requests, such
        /// as the AcmeOrder URL, will be copied over.
        /// </para>
        /// </remarks>
        public async Task<AcmeOrderDetails> GetOrderDetailsAsync(string orderUrl)
        {
            var method = _usePostAsGet ? HttpMethod.Post : HttpMethod.Get;
            var resp = await SendAcmeAsync(
                    orderUrl,
                    responseType: AcmeJson.Insensitive.AcmeOrder,
                    method: method);
            return DecodeOrderResponse(resp, orderUrl);
        }

        /// <summary>
        /// Retrieves the details of an AcmeAuthorization associated with a previously
        /// created AcmeOrder.  The AcmeAuthorization details URL is returned as part of
        /// an AcmeOrder's response.
        /// </summary>
        /// <remarks>
        /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.5
        /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.1.4
        /// <para>
        /// Use this operation to retrieve the initial details of an AcmeAuthorization,
        /// such as immediately after creating a new AcmeOrder, as well as to retrieve
        /// the subsequent state and progress of an AcmeAuthorization, such as as after
        /// responding to an associated AcmeChallenge.
        /// </para>
        /// </remarks>
        public async Task<AcmeAuthorization> GetAuthorizationDetailsAsync(string authzDetailsUrl)
        {
            var method = _usePostAsGet ? HttpMethod.Post : HttpMethod.Get;
            var typedResp = await SendAcmeAsync(
                    authzDetailsUrl,
                    AcmeJson.Insensitive.AcmeAuthorization,
                    method: method);
            if (typedResp.Value == null)
            {
                throw new Exception("Invalid response");
            }
            return typedResp.Value;
        }

        /// <summary>
        /// Deactivates a specific AcmeAuthorization and thereby relinquishes the
        /// authority to issue Certificates for the associated AcmeIdentifier.
        /// </summary>
        /// <remarks>
        /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.5.2
        /// </remarks>
        public async Task<AcmeAuthorization> DeactivateAuthorizationAsync(string authzDetailsUrl)
        {
            var typedResp = await SendAcmeAsync(
                    authzDetailsUrl,
                    responseType: AcmeJson.Insensitive.AcmeAuthorization,
                    requestType: AcmeJson.Insensitive.DeactivateAuthorizationRequest,
                    message: new DeactivateAuthorizationRequest());
            if (typedResp.Value == null)
            {
                throw new Exception("Invalid response");
            }
            return typedResp.Value;
        }

        /// <summary>
        /// </summary>
        /// <remarks>
        /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.5.1
        /// </remarks>
        public async Task<AcmeChallenge> GetChallengeDetailsAsync(string challengeDetailsUrl)
        {
            var method = _usePostAsGet ? HttpMethod.Post : HttpMethod.Get;
            var typedResp = await SendAcmeAsync(
                    challengeDetailsUrl,
                    AcmeJson.Insensitive.AcmeChallenge,
                    method: method);
            if (typedResp.Value == null)
            {
                throw new Exception("Invalid response");
            }
            return typedResp.Value;
        }

        /// <summary>
        /// </summary>
        /// <remarks>
        /// https://datatracker.ietf.org/doc/draft-ietf-acme-ari/
        /// </remarks>
        public async Task<AcmeRenewalInfo?> GetRenewalInfo(string certificateId)
        {
            if (string.IsNullOrWhiteSpace(Directory.RenewalInfo))
            {
                return null;
            }
            var typedResp = await SendAcmeAsync(
                Directory.RenewalInfo.TrimEnd('/') + '/' + certificateId,
                AcmeJson.Insensitive.AcmeRenewalInfo,
                method: HttpMethod.Get);
            if (typedResp.Value == null)
            {
                throw new Exception("Invalid response");
            }
            return typedResp.Value;
        }

        /// <summary>
        /// Tell the server that we don't care about a certificate anymore,
        /// e.g. don't send us emails that 
        /// </summary>
        /// <param name="certificateId"></param>
        /// <returns></returns>
        public async Task UpdateRenewalInfo(byte[] certificateId)
        {
            if (string.IsNullOrWhiteSpace(Directory.RenewalInfo))
            {
                return;
            }
            var request = new UpdateRenewalInfoRequest()
            {
                CertificateId = Base64Tool.UrlEncode(certificateId),
                Replaced = true
            };
            var serialized = JsonSerializer.Serialize(request, AcmeJson.Insensitive.UpdateRenewalInfoRequest);
            serialized = ComputeAcmeSigned(serialized, Directory.RenewalInfo);
            _ = await SendAcmeAsync(
                Directory.RenewalInfo,
                message: serialized);
        }

        /// <summary>
        /// </summary>
        /// <remarks>
        /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.5.1
        /// </remarks>
        public async Task<AcmeChallenge> AnswerChallengeAsync(string challengeDetailsUrl)
        {
            var typedResp = await SendAcmeAsync(challengeDetailsUrl, AcmeJson.Insensitive.Object, AcmeJson.Insensitive.AcmeChallenge, message: new());
            if (typedResp.Value == null)
            {
                throw new Exception("Invalid response");
            }
            return typedResp.Value;
        }

        /// <summary>
        /// </summary>
        /// <remarks>
        /// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.4
        /// </remarks>
        public async Task<AcmeOrderDetails> FinalizeOrderAsync(AcmeOrderDetails details, byte[] derEncodedCsr)
        {
            var message = new FinalizeOrderRequest
            {
                Csr = Base64Tool.UrlEncode(derEncodedCsr),
            };
            if (details.Payload.Finalize == null)
            {
                throw new InvalidOperationException("Missing finalize url");
            }
            var resp = await SendAcmeAsync(
                    details.Payload.Finalize,
                    requestType: AcmeJson.Insensitive.FinalizeOrderRequest,
                    responseType: AcmeJson.Insensitive.AcmeOrder,
                    expectedStatuses: [HttpStatusCode.OK, HttpStatusCode.Created],
                    message: message);

            return DecodeOrderResponse(resp, details.OrderUrl);
        }

        /// <summary>
        /// Get ACME certificate including metadata
        /// </summary>
        /// <param name="order"></param>
        /// <returns></returns>
        public async Task<AcmeCertificate> GetOrderCertificateExAsync(AcmeOrderDetails order)
        {
            if (order.Payload.Certificate == null)
            {
                throw new InvalidOperationException();
            }
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
            if (string.IsNullOrEmpty(Directory.RevokeCert))
            {
                throw new NotSupportedException();
            }
            var message = new RevokeCertificateRequest
            {
                Certificate = Base64Tool.UrlEncode(derEncodedCertificate),
                Reason = reason
            };
            var serialized = JsonSerializer.Serialize(message, AcmeJson.Insensitive.RevokeCertificateRequest);
            serialized = ComputeAcmeSigned(serialized, Directory.RevokeCert);
            // If OK is returned, we're all done. Otherwise general exception handling will kick in
            _ = await SendAcmeAsync(
                    Directory.RevokeCert,
                    message: serialized,
                    expectedStatuses: [HttpStatusCode.OK]);
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
            var method = _usePostAsGet ? HttpMethod.Post : HttpMethod.Get;
            var resp = await SendAcmeAsync(relativeUrl, method);
            _ = resp.EnsureSuccessStatusCode();
            return resp;
        }

        /// <summary>
        /// The workhorse routine for submitting HTTP requests using ACME protocol
        /// semantics and activating pre- and post-submission event hooks.
        /// </summary>
        /// <param name="relativeUri">URI to send to</param>
        /// <param name="method">HTTP Method to use, defaults to <c>GET</c></param>
        /// <param name="message">Optional request payload, will be JSON-serialized</param>
        /// <param name="expectedStatuses">Any HTTP response statuses that can be interpretted
        ///         as successful, defaults to <c>OK (200)</c>; other response statuses will
        ///         trigger an exception; you can also skip response status checking by supplying
        ///         a zero-length array value here</param>
        /// <param name="opName">Name of operation, will be auto-populated with calling method
        ///         name if unspecified</param>
        /// <returns>The returned HTTP response message, unaltered, after inspecting the
        ///         response details for possible error or problem result</returns>
        async Task<HttpResponseMessage> SendAcmeAsync(
            string relativeUri,
            HttpMethod? method = null,
            string? message = null,
            HttpStatusCode[]? expectedStatuses = null,
            [System.Runtime.CompilerServices.CallerMemberName] string opName = "")
        {
            method ??= HttpMethod.Post;
            expectedStatuses ??= [HttpStatusCode.OK];

            var uri = new Uri(_http.BaseAddress!, relativeUri);
            var requ = new HttpRequestMessage(method, uri);
            var skipNonce = method == HttpMethod.Get;

            if (string.IsNullOrEmpty(message) && method == HttpMethod.Post)
            {
                message = ComputeAcmeSigned("", uri.ToString());
            } 
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
        /// <param name="includePublicKey"></param>
        /// <param name="opName"></param>
        /// <returns></returns>
        async Task<Response<TResponse>> SendAcmeAsync<TResponse, TRequest>(
            string uri, JsonTypeInfo<TRequest> requestType, JsonTypeInfo<TResponse> responseType,
            HttpMethod? method = null, TRequest? message = null, HttpStatusCode[]? expectedStatuses = null,
            bool includePublicKey = false,
            [System.Runtime.CompilerServices.CallerMemberName] string opName = "")
            where TRequest : class
        {
            string? payload = null;
            if (message != null)
            {
                payload = JsonSerializer.Serialize(message, requestType);
                payload = ComputeAcmeSigned(payload, uri, includePublicKey: includePublicKey);
            }
            var response = await SendAcmeAsync(uri, method, payload, expectedStatuses, opName);
            return new Response<TResponse>(response)
            {
                Value = await Deserialize(response, responseType)
            };
        }

        public class Response<TResponse>(HttpResponseMessage message)
        {
            public HttpResponseMessage Message { get; init; } = message;
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
        /// <param name="opName"></param>
        /// <returns></returns>
        async Task<Response<TResponse>> SendAcmeAsync<TResponse>(
            string uri, JsonTypeInfo<TResponse> responseType,
            string? message = null, HttpMethod? method = null, HttpStatusCode[]? expectedStatuses = null,
            [System.Runtime.CompilerServices.CallerMemberName] string opName = "")
        {
            var response = await SendAcmeAsync(uri, method, message, expectedStatuses, opName);
            return new Response<TResponse>(response)
            {
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
            _ = resp.Message.Headers.TryGetValues("Link", out var linkValues);
            var links = new HTTP.LinkCollection(linkValues); // This allows/handles null
            var tosLink = links.GetFirstOrDefault(Constants.TosLinkHeaderRelationKey)?.Uri;
            if (resp.Value == default)
            {
                throw new InvalidDataException();
            }
            var acctUrl = resp.Message.Headers.Location?.ToString();
            var acct = new AccountDetails
            {
                Payload = resp.Value,
                Kid = acctUrl ?? existing?.Kid ?? throw new InvalidDataException("Missing KID"),
                TosLink = tosLink ?? existing?.TosLink
            };
            return acct;
        }

        protected static AcmeOrderDetails DecodeOrderResponse(Response<AcmeOrder> resp, string? originalUrl = null)
        {
            var orderUrl = resp.Message.Headers.Location?.ToString();
            if (resp.Value == null)
            {
                throw new InvalidOperationException("missing order");
            }
            var order = new AcmeOrderDetails(resp.Value)
            {
                OrderUrl = orderUrl ?? originalUrl
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
        protected string ComputeAcmeSigned(
            string message, 
            string requUrl,
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
            var jwsFlatJS = SignFlatJsonAsObject(signer.Sign, message, protectedHeaderSer);
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
