using System.Net;

namespace FunctionApp.SentinelLogging.Utilities
{
    // The validation and sanitization methods in this class are merely examples for simple demonstration purposes. Production code should be more thorough.
    public static class Validator
    {
        public static bool IsValidIpAddress(string ipAddress)
        {
            return IPAddress.TryParse(ipAddress, out _);
        }

        public static bool IsValidPort(int port)
        {
            return port > 0 && port <= 65535;
        }

        public static bool IsValidHttpMethod(string method)
        {
            var allowedMethods = new[] { "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD" };
            return allowedMethods.Contains(method.ToUpperInvariant());
        }

        public static bool IsValidProtocol(string protocol)
        {
            return protocol == "http" || protocol == "https";
        }

        public static bool IsValidHostName(string hostName)
        {
            return Uri.CheckHostName(hostName) != UriHostNameType.Unknown;
        }

        public static bool IsValidUserId(string? userId)
        {
            return Guid.TryParse(userId, out _);
        }

        public static bool IsValidRequestUri(string requestUri)
        {
            // Check for null or empty URI
            if (string.IsNullOrWhiteSpace(requestUri))
            {
                return false;
            }

            // Check length (most legitimate URIs are under 2048 characters)
            if (requestUri.Length > 2048)
            {
                return false;
            }

            // Check for null bytes which could indicate injection attempts
            if (requestUri.Contains('\0'))
            {
                return false;
            }

            // Check if the URI is well-formed
            if (!Uri.IsWellFormedUriString(requestUri, UriKind.RelativeOrAbsolute))
            {
                return false;
            }

            // Parse the URI for further validation
            if (!Uri.TryCreate(requestUri, UriKind.RelativeOrAbsolute, out var uri))
            {
                return false;
            }

            // For absolute URIs, verify scheme
            if (uri.IsAbsoluteUri)
            {
                // Only allow http and https schemes
                if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
                {
                    return false;
                }

                // Validate host for absolute URIs
                if (!IsValidHostName(uri.Host))
                {
                    return false;
                }
            }

            // Check for path traversal attempts
            string path = uri.IsAbsoluteUri ? uri.AbsolutePath : requestUri;
            if (path.Contains("../") || path.Contains("..\\") ||
                path.Contains("%2e%2e%2f") || path.Contains("%2e%2e/") ||
                path.Contains("..%2f") || path.Contains("%252e%252e%252f"))
            {
                return false;
            }

            // Check for dangerous patterns
            var dangerousPatterns = new[]
            {
                "<script", "javascript:", "data:", "vbscript:",
                "file:", "ftp:", "ws:", "wss:", "gopher:",
                "expression(", "xss:", "livescript:", "mocha:"
            };

            foreach (var pattern in dangerousPatterns)
            {
                if (requestUri.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return false;
                }
            }

            // Check for suspicious character sequences
            var suspiciousSequences = new[]
            {
                "&#", "\\x", "%3C", "%3E", "%00", "%25", "\\u"
            };

            foreach (var seq in suspiciousSequences)
            {
                if (requestUri.IndexOf(seq, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return false;
                }
            }

            // Check for excessive use of encoded characters (potential obfuscation)
            int encodedCount = 0;
            for (int i = 0; i < requestUri.Length - 2; i++)
            {
                if (requestUri[i] == '%' && Uri.IsHexDigit(requestUri[i + 1]) && Uri.IsHexDigit(requestUri[i + 2]))
                {
                    encodedCount++;
                }
            }

            // If more than 30% of the URI consists of encoded characters, it's suspicious
            if (encodedCount > 0 && (double)encodedCount / requestUri.Length > 0.3)
            {
                return false;
            }

            return true;
        }

        public static bool IsValidUserAgent(string userAgent)
        {
            // Check for null or empty user agent
            if (string.IsNullOrWhiteSpace(userAgent))
            {
                return false;
            }

            // Check length (most legitimate user agents are under 512 characters)
            if (userAgent.Length > 512)
            {
                return false;
            }

            // Check for overly simple user agents that might be scripts
            if (userAgent.Length < 5)
            {
                return false;
            }

            // Check for null bytes which could indicate injection attempts
            if (userAgent.Contains('\0'))
            {
                return false;
            }

            // Check for common attack tool signatures
            var suspiciousTools = new[]
            {
                "sqlmap", "nikto", "nessus", "dirbuster", "hydra", "gobuster",
                "burpsuite", "acunetix", "nmap", "zap", "metasploit", "masscan",
                "wfuzz", "nikto", "paros"
            };

            foreach (var tool in suspiciousTools)
            {
                if (userAgent.IndexOf(tool, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return false;
                }
            }

            // Check for overly simple user agents that might be scripts
            if (userAgent.Length < 5)
            {
                return false;
            }

            // Check for control characters that shouldn't be in a user agent
            for (int i = 0; i < userAgent.Length; i++)
            {
                char c = userAgent[i];
                if (c < 32 && c != 9) // Allow tab (9) but no other control chars
                {
                    return false;
                }
            }

            // Check for common XSS/injection patterns
            var injectionPatterns = new[]
            {
                "<script", "javascript:", "onerror=", "onload=", "onclick=",
                "data:", "vbscript:", "expression(", "url(", "document.cookie"
            };

            foreach (var pattern in injectionPatterns)
            {
                if (userAgent.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return false;
                }
            }

            // Optional: Verify it follows a common user agent pattern
            // Most user agents contain browser info, OS info, or bot identity
            bool hasCommonPattern = userAgent.Contains("/") ||
                                   userAgent.Contains("Mozilla") ||
                                   userAgent.Contains("Bot") ||
                                   userAgent.Contains("Spider") ||
                                   userAgent.Contains("Crawler");

            if (!hasCommonPattern && userAgent.Length > 15)
            {
                // Suspicious if long and doesn't match common patterns
                return false;
            }

            return true;
        }              

        public static string SanitizeInput(string input)
        {
            // This is only an example
            return input.Replace("<", "").Replace(">", "").Replace("\"", "").Replace("'", "");
        }        
    }
}
