using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;

namespace FunctionApp.SentinelLogging
{
    public class LogEvents
    {
        private readonly ILogger<LogEvents> _logger;

        public LogEvents(ILogger<LogEvents> logger)
        {
            _logger = logger;
        }

        [Function(nameof(LogEvents))]
        public IActionResult Run([HttpTrigger(AuthorizationLevel.Anonymous, "get", "post")] HttpRequest req)
        {
            _logger.LogInformation("C# HTTP trigger function processed a request.");
            return new OkObjectResult("Welcome to Azure Functions!");
        }
    }
}
