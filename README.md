# FunctionApp.SentinelLogging

## Setup instructions

### Create Azure resources

Create a new resource group for the resources while adhering to your organization's naming conventions.

#### Data Collection Endpoint

1. Create a new data collection endpoint resource while adhering to your organization's naming conventions.
1. Note down the _Logs Ingestion_ endpoint URL from the Overview blade.

#### Log Analytics Workspace

1. Create a new log analytics workspace.
1. Create a new custom table with a descriptive name in the log analytics workspace (e.g., AppSecurityEvents). 
   - Select DCR-based log.
   - Create a new data collection rule (adhere to your organization's naming conventions) and select the data collection endpoint you created earlier.
   - Use the log-sample.json file in the root folder as a sample for the schema.
   - Use the following transformer to get rid of the error.<br/>
     `source | extend TimeGenerated = todatetime(timestamp)`

#### Data Collection Rule

1. This resource was created when you created the custom table for log analytics.
1. Note down the immutable ID of the data collection rule. You can find it in the Overview blade of the data collection rule resource.

#### Azure Function App

1. Create a Function App via the Azure portal.
1. Enable its managed identity.
1. Go to Environment variables and add the following settings:

   | Name | Value | Description |
   | -- | -- | -- |
   | AppId | App identifier | Included in log entries. |
   | DCR_DataSource | Custom-TableName_CL | Your custom log analytics workspace table name. Always starts with Custom- and ends with _CL. |
   | DCE_LogsIngestionUrl | https://your-dce-xyz.region-1.ingest.monitor.azure.com | Logs Ingestion endpoint URL from the Data Collection Endpoint resource Overview blade. |
   | DCR_ImmutableId | dcr-immutable-id | Immutable Id from the Data Collection Rule resource Overview blade.|

### Code publishing

For these kinds of quick demo purposes, we can publish the code using publish profiles. In production scenarios, always use CI/CD pipelines to publish code to Azure services.

1. enable _SCM Basic Auth Publishing Credentials_ under Configuration -> General.
1. Download the publish profile from the Overview blade
1. Use the publish profile to publish function project code to the function app.

> :exclamation: Never check in publish profiles to version control! Add them to .gitignore.

### Local debugging

1. Create a `local.settings.json` file in the project root folder.
1. Create an Entra ID application registration with a client secret.
1. Add the following entries to the `local.settings.json` file `Values` section:
```json
{
  "IsEncrypted": false,
  "Values": {
    "AzureWebJobsStorage": "UseDevelopmentStorage=true",
    "FUNCTIONS_WORKER_RUNTIME": "dotnet-isolated",

    "DCR_DataSource": "Custom-TableName_CL",
    "DCE_LogsIngestionUrl": "https://your-dce-xyz.region-1.ingest.monitor.azure.com",
    "DCR_ImmutableId": "dcr-immutable-id",

    "TenantId": "your-tenant-id",
    "ClientId": "your-client-id",
    "ClientSecret": "your-client-secret"
  }
}
```

### Permissions

You need to grant the service principal and/or function app managed identity _Monitoring Metrics Publisher_ role on the data collection rule resource. It can take a bit for the permissions to come into effect.