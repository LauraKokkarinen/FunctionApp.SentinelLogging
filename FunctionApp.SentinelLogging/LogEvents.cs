using FunctionApp.SentinelLogging.Interfaces;
using Microsoft.ApplicationInsights.DataContracts;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;

namespace FunctionApp.SentinelLogging
{
    public class LogEvents(ILogAnalyticsService logAnalyticsService)
    {
        private readonly ILogAnalyticsService _logAnalyticsService = logAnalyticsService;

        [Function(nameof(LogEvents))]
        public IActionResult Run([HttpTrigger(AuthorizationLevel.Anonymous, "get", "post")] HttpRequest req)
        {
            string hostName = req.HttpContext.Request.Host.Host;
            string hostIp = req.HttpContext.Connection.LocalIpAddress?.ToString() ?? "Unknown";
            int port = req.HttpContext.Connection.LocalPort;
            string requestMethod = req.Method;
            string protocol = req.Scheme;            
            string requestUri = req.Path.ToString();
            string sourceIp = req.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
            string userAgent = req.Headers["User-Agent"].ToString();

            // TODO: Validate and sanitize input

            _logAnalyticsService.Initialize(hostIp, port, requestMethod, protocol, hostName, requestUri, sourceIp, userAgent);

            _logAnalyticsService.LogEvent(SeverityLevel.Information, "EventName", "Description");

            return new NoContentResult();
        }
    }
}
