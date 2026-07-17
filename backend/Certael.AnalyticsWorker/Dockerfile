FROM mcr.microsoft.com/dotnet/sdk:10.0.201@sha256:bf523a128915a223f302abf406b69b7ee7585a3874cc6ac2756e09df5f345187 AS build
WORKDIR /src
COPY . .
RUN dotnet publish backend/Certael.AnalyticsWorker/Certael.AnalyticsWorker.csproj -c Release -o /app /p:UseAppHost=false
FROM mcr.microsoft.com/dotnet/runtime:10.0.3@sha256:3c621f21692b64bc236e89452f41c904ae4942d8bfcae15efda9486e0ef0c56f
WORKDIR /app
COPY --from=build /app .
USER $APP_UID
ENTRYPOINT ["dotnet", "Certael.AnalyticsWorker.dll"]
