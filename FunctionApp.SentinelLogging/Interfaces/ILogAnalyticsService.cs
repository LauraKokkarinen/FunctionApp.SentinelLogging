using Microsoft.ApplicationInsights.DataContracts;

namespace FunctionApp.SentinelLogging.Interfaces
{
    public interface ILogAnalyticsService
    {
        Task Initialize(string hostIp, int port, string requestMethod, string protocol, string hostName, string requestUri, string sourceIp, string userAgent, string? principalId = null);
        Task LogEventAsync(SeverityLevel level, string eventName, string description);
    }
}
