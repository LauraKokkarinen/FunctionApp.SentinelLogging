using FunctionApp.SentinelLogging.Interfaces;
using Microsoft.ApplicationInsights.DataContracts;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using System.Diagnostics;
using System.Text.Json;
using System.Text;
using FunctionApp.SentinelLogging.Types;

namespace FunctionApp.SentinelLogging
{
    public class LogEvents(ILogAnalyticsService logAnalyticsService)
    {
        private readonly ILogAnalyticsService _logAnalyticsService = logAnalyticsService;

        [Function(nameof(LogEvents))]
        public async Task<IActionResult> RunAsync([HttpTrigger(AuthorizationLevel.Anonymous, "get", "post")] HttpRequest req)
        {
            string hostName = req.HttpContext.Request.Host.Host;
            string hostIp = req.HttpContext.Connection.LocalIpAddress?.ToString() ?? "Unknown";
            int port = req.HttpContext.Connection.LocalPort;
            string requestMethod = req.Method;
            string protocol = req.Scheme;            
            string requestUri = req.Path.ToString();
            string sourceIp = req.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
            string userAgent = req.Headers["User-Agent"].ToString();

            var userId = "00000000-0000-0000-0000-000000000000"; // Could also be application identity

            if (!Debugger.IsAttached)
            {
                var principal = JsonSerializer.Deserialize<Principal>(Encoding.UTF8.GetString(Convert.FromBase64String(req.Headers["X-MS-CLIENT-PRINCIPAL"].ToString())));
                userId = principal?.Claims?.FirstOrDefault(claim => claim.Type == "oid")?.Value;
            }            

            // Validate and sanitize input to be used in log service initialization at this point

            _logAnalyticsService.Initialize(hostIp, port, requestMethod, protocol, hostName, requestUri, sourceIp, userAgent); // Could also initialize with userId if desired to be present in all log entries.

            // Example values to log
            var retries = 4;
            var maxlimit = 5;
            var reason = "maxretries";
            var region1 = "US-OR";
            var region2 = "CN-SH";
            var api = "api.azure.com";
            var scopes = "read,write";
            var tokenId = "xyz";
            var resource = "file.docx";
            var role1 = "user";
            var role2 = "admin";
            var adminEvent = "user_privilege_change";
            var adminEventDescription = $"updated privileges of user user@domain.com from user to admin";
            var fileName = "file.png";
            var fileType = "PNG";
            var from = "C:\\temp\\file.png";
            var to = "C:\\temp\\file-renamed.png";
            var validation = "virusscan";
            var status = "FAILED";
            var fileId = "1234567890";
            var fieldId = "date_of_birth";
            var inputName = "creditcardnum";
            var toolname = "Nikto";
            var referrer = "illegal.origin.com";
            var path = "C:\\temp\\file.docx";

            // Log events from https://cheatsheetseries.owasp.org/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html
            // Use threat modeling to identify relevant events for your application

            // Can also be found on identity provider logs (e.g., Microsoft Entra ID)
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Information, $"authn_login_success:{userId}", $"User {userId} logged in successfully.");
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Information, $"authn_login_successafterfail:{userId},{retries}", $"User {userId} logged in successfully after {retries} failed attempts.");
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Warning, $"authn_login_fail:{userId}", $"User {userId} failed to log in.");
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Warning, $"authn_login_fail_max:{userId},{maxlimit}", $"User {userId} reached the login fail limit of {maxlimit}.");
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Warning, $"authn_login_lock:{userId},{reason}", $"User {userId} account is now locked because of {reason}."); // Should rather be done by Sentinel based on log entries.
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Information, $"authn_password_change:{userId}", $"User {userId} successfully changed their password.");
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Critical, $"authn_password_change_fail:{userId}", $"User {userId} failed to change their password.");
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Critical, $"authn_impossible_travel:{userId},{region1},{region2}", $"User {userId} is logged in from two distant locations at the same time.");
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Information, $"authn_token_created:{userId},{api},{scopes}", $"User {userId} created a token for {api} with permissions {scopes}.");
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Information, $"authn_token_revoked:{userId},{api},{tokenId}", $"User {userId} token {tokenId} for {api} has now been revoked.");
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Critical, $"authn_token_reuse:{userId},{api},{tokenId}", $"User {userId} attempted to use token {tokenId} for {api} which was previously revoked.");
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Warning, $"authn_token_delete:{userId},{api},{tokenId}", $"User {userId} token {tokenId} for {api} has now been deleted.");

            // An attempt was made to access a resource which was unauthorized
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Critical, $"authz_fail:{userId},{resource}", $"User {userId} attempted to access resource {resource} without entitlement."); // Direct object references are logged separately
            
            // The user or entity entitlements was changed
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Warning, $"authz_change:{userId},{role1},{role2}", $"User {userId} role was changed from {role1} to {role2}.");

            // All activity by privileged users such as admin should be recorded.
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Warning, $"authz_admin:{userId},{adminEvent}", $"Admin {userId} has {adminEventDescription}.");

            // When a user exceeds the rate limit for a service it can be an indication of abuse.
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Warning, $"excess_rate_limit_exceeded:{userId},{maxlimit}", $"User {userId} has exceeded max {maxlimit} request limit.");

            // On successful file upload, the first step in the validation process is that the upload has completed.
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Information, $"upload_complete:{userId},{fileName},{fileType}", $"User {userId} has uploaded {fileName}.");

            // One step in good file upload validation is to move/rename the file and when providing the content back to end users, never reference the original filename in the download. This is true both when storing in a filesystem as well as in block storage.
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Information, $"upload_stored:{fileName},{from},{to}", $"File {fileName} was copied from {from} to {to}.");

            // All file uploads should have some validation performed, both for correctness (is in fact of file type x), and for safety (does not contain a virus).
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Critical, $"upload_validation:{fileName},{validation},{status}", $"File {fileName} {status} {validation} validation."); // Purge the file if the validation fails.

            // When a file is deleted for normal reasons it should be recorded.
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Information, $"upload_delete:{userId},{fileId}", $"User {userId} deleted file {fileId}.");

            // When input validation fails on the server-side it must either be because a) sufficient validation was not provided on the client, or b) client-side validation was bypassed. In either case it's an opportunity for attack and should be mitigated quickly.
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Warning, $"input_validation_fail:{userId},{fieldId}", $"User {userId} submitted data to field {fieldId} that failed validation."); // Don't log the submitted data because it could be sensitive or an attack string.

            // When a user makes numerous requests for files that don't exist it often is an indicator of attempts to "force-browse" for files that could exist and is often behavior indicating malicious intent.
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Warning, $"malicious_excess_404:{userId}", $"User {userId} caused a large number of 404 errors.");

            // When a user submits data to a backend handler that was not expected, it can indicate probing for input validation errors. If your backend service receives data it does not handle or have an input for, it is an indication of likely malicious abuse.
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Critical, $"malicious_extraneous:{userId},{inputName}", $"User {userId} included field {inputName} in the request which is not handled by this service.");

            // When obvious attack tools are identified either by signature or by user agent they should be logged. For example, the tool "Nikto" leaves behind its user agent by default with a string like "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:Port Check)"
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Critical, $"malicious_attack_tool:{userId},{toolname}", $"User {userId} caused traffic indicating use of attack tool {toolname}.");

            // When attempts are made from unauthorized origins they should of course be blocked, but also logged whenever possible. Even if we block an illegal cross-origin request the fact that the request is being made could be an indication of attack.
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Critical, $"malicious_cors:{userId},{referrer}", $"User {userId} made an illegal cross-origin request from {referrer}.");

            // A common attack against authentication and authorization is to directly access an object without credentials or appropriate access authority. Failing to prevent this flaw used to be one of the OWASP Top Ten called Insecure Direct Object Reference. Assuming you've correctly prevented this attack, logging the attempt is valuable to identify malicious users.
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Critical, $"malicious_direct_reference:{userId}", $"User {userId} attempted to access an object to which they are not authorized.");

            // Tracking changes to objects to which there are access control restrictions can uncover attempt to escalate privilege on those files by unauthorized users.
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Warning, $"privilege_permissions_changed:{userId}", $"User {userId} changed permissions");

            // When a user reaches a part of the application out of sequence it may indicate intentional abuse of the business logic and should be tracked.
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Critical, $"sequence_fail:{userId}", $"User {userId} has reached a part of the application out of the normal application flow.");

            // When a new piece of data is created and marked as sensitive or placed into a directory/table/repository where sensitive data is stored, that creation should be logged and reviewed periodically.
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Warning, $"sensitive_create:{userId},{path}", $"User {userId} created a new resource at {path}.");

            // All data marked as sensitive or placed into a directory/table/repository where sensitive data is stored should be have access logged and reviewed periodically.
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Warning, $"sensitive_read:{userId},{path}", $"User {userId} read resource at {path}.");

            // All data marked as sensitive or placed into a directory/table/repository where sensitive data is stored should be have updates to the data logged and reviewed periodically.
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Warning, $"sensitive_update:{userId},{path}", $"User {userId} modified resource at {path}.");

            //  All data marked as sensitive or placed into a directory/table/repository where sensitive data is stored should have deletions of the data logged and reviewed periodically. The file should not be immediately deleted but marked for deletion and an archive of the file should be maintained according to legal/privacy requirements.
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Warning, $"sensitive_delete:{userId},{path}", $"User {userId} marked resource at {path} for deletion.");

            // Can also be found on identity provider logs (e.g., Microsoft Entra ID)
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Information, $"session_created:{userId}", $"User {userId} created session");
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Information, $"session_renewed:{userId}", $"User {userId} renewed session");
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Information, $"session_expired:{userId}", $"User {userId} session expired");
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Critical, $"session_use_after_expire:{userId}", $"User {userId} used session after expiration");

            // Can also be found on cloud service provider logs (e.g., Microsoft Azure)
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Warning, $"sys_startup:{userId}", $"User {userId} system startup");
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Warning, $"sys_shutdown:{userId}", $"User {userId} system shutdown");
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Warning, $"sys_restart:{userId}", $"User {userId} system restart");
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Warning, $"sys_crash:{userId}", $"User {userId} system crash");
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Warning, $"sys_monitor_disabled:{userId}", $"User {userId} disabled system monitor");
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Warning, $"sys_monitor_enabled:{userId}", $"User {userId} enabled system monitor");

            // Can also be found on identity provider logs (e.g., Microsoft Entra ID)
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Warning, $"user_created:{userId}", $"User {userId} created user.");
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Warning, $"user_updated:{userId}", $"User {userId} updated user.");
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Warning, $"user_disabled:{userId}", $"User {userId} disabled user.");
            await _logAnalyticsService.LogEventAsync(SeverityLevel.Warning, $"user_deleted:{userId}", $"User {userId} deleted user.");

            return new NoContentResult();
        }
    }
}
