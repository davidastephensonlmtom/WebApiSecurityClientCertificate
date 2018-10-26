using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using WebApiSecurityExample1.Options;

namespace WebApiSecurityExample1.Middlewares
{
    /// <summary>
    /// Middleware to validate client certificate 
    /// e.g API GW communicating with backend provider API over Https and
    /// furnishes a client certificate to the latter
    /// </summary>
    public class ValidateCertificateMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IOptions<ClientCertValidationOptions> _options;
        private readonly IOptions<HttpsOptions> _httpsOptions;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="next">The next Delegate in pipeline</param>
        /// <param name="options"></param>
        /// <param name="httpsOptions"></param>
        public ValidateCertificateMiddleware(RequestDelegate next, IOptions<ClientCertValidationOptions> options, IOptions<HttpsOptions> httpsOptions)
        {
            _next = next;
            _options = options;
            _httpsOptions = httpsOptions;
        }

        /// <summary>
        /// Invoke method called when the Middleware is used
        /// </summary>
        /// <param name="context">HttpContext</param>
        /// <returns></returns>
        public async Task Invoke(HttpContext context)
        {
           
            // String to hold the expected CN of incoming client certificate
            var expectedClientCertificateCn = _options.Value.ValidateToCn;

            // Check if Ssl is enabled i.e communication is happening over Https
            if (_httpsOptions.Value.SslEnabled)
            {
                // Declare a X509Certificate2 type variable
                X509Certificate2 clientCertificate = null;
                try
                {
                    // Extract X509Certificate2 certificate instance from ConnectionInfo of context
                    clientCertificate = context.Connection.ClientCertificate;

                    // If not present in ConnectionInfo
                    if (clientCertificate == null)
                    {
                        // Extract Certificate held as Base64String from the Request Header named "X-ARR-ClientCert" 
                        var clientCertificateInHeader = context.Request.Headers["X-ARR-ClientCert"];

                        // Check for null or empty value
                        if (!string.IsNullOrEmpty(clientCertificateInHeader))
                        {
                            // Instantiate into X509Certificate2
                            clientCertificate = new X509Certificate2(Convert.FromBase64String(clientCertificateInHeader));
                        }
                    }

                    // By this time, clientCertificate should be populated
                    // If still null, a Response Status Code of 403 should be set and pipeline short-circuited
                    if (clientCertificate == null) 
                    {
                        // Set Response status code to 403/Unauthorized
                        context.Response.StatusCode = 403;
                    }
                    else // Start certificate validation
                    {
                        try
                        {
                            // Get CN from Certificate
                            var commonName = clientCertificate.GetNameInfo(X509NameType.SimpleName, false);

                            // Check that CN is not null/empty
                            // AND CN is equal to the expected CN
                            // AND SubjectName is NOT EQUAL TO IssuerName
                            if (!string.IsNullOrEmpty(commonName)
                                && commonName.Equals(expectedClientCertificateCn, StringComparison.InvariantCultureIgnoreCase)
                                && !clientCertificate.SubjectName.RawData.SequenceEqual(clientCertificate.IssuerName.RawData))
                            {
                                // Client certificate is valid
                                // Allow request to hit the next middleware in pipeline
                                await _next.Invoke(context);
                            }
                            else
                            {
                                // Response Status Code of 403 should be set and pipeline short-circuited
                                context.Response.StatusCode = 403;
                            }
                        }
                        catch (Exception ex) // In the event of an exception
                        {
                            // Write error message to response / or take other appropriate action
                            await context.Response.WriteAsync(ex.Message);

                            // Response Status Code of 403 should be set and pipeline short-circuited
                            context.Response.StatusCode = 403;
                        }
                    }
                }
                finally
                {
                    // Dispose the extracted X509Certificate2 object
                    clientCertificate?.Dispose();
                }
                
            }
            else
            {
                // Call the next middleware
                await _next.Invoke(context);
            }
        }
    }
}