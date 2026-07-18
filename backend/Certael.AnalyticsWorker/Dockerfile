FROM mcr.microsoft.com/dotnet/sdk:10.0@sha256:ed034a8bf0b24ded0cbbac07e17825d8e9ebfe21e308191d0f7421eaf5ad4664 AS build
WORKDIR /src
COPY . .
RUN dotnet publish backend/Certael.AnalyticsWorker/Certael.AnalyticsWorker.csproj -c Release -o /app /p:UseAppHost=false
FROM mcr.microsoft.com/dotnet/runtime:10.0@sha256:ed5d539b27842d656a06a5984dbcb5114d3e885fbada612a49a5a7c3c3a44e1c
ARG SOURCE_REVISION=unknown
LABEL org.opencontainers.image.source="https://github.com/violetweather/Certael" \
      org.opencontainers.image.revision="$SOURCE_REVISION" \
      org.opencontainers.image.licenses="Apache-2.0"
WORKDIR /app
COPY --from=build /app .
COPY LICENSE /licenses/LICENSE
USER $APP_UID
ENTRYPOINT ["dotnet", "Certael.AnalyticsWorker.dll"]
