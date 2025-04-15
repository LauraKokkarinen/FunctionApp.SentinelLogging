using FunctionApp.SentinelLogging.Interfaces;
using FunctionApp.SentinelLogging.Services;
using Microsoft.Azure.Functions.Worker.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = FunctionsApplication.CreateBuilder(args);

builder.ConfigureFunctionsWebApplication();

builder.Services.AddSingleton<ILogAnalyticsService, LogAnalyticsService>();
// Application Insights isn't enabled by default. See https://aka.ms/AAt8mw4.
//     .AddApplicationInsightsTelemetryWorkerService()
//     .ConfigureFunctionsApplicationInsights();

builder.Build().Run();
