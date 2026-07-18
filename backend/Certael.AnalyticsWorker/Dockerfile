FROM mcr.microsoft.com/dotnet/sdk:10.0@sha256:ea8bde36c11b6e7eec2656d0e59101d4462f6bd630730f2c8201ed0572b295d5 AS build
WORKDIR /src
COPY . .
RUN dotnet publish backend/Certael.AnalyticsWorker/Certael.AnalyticsWorker.csproj -c Release -o /app /p:UseAppHost=false
FROM mcr.microsoft.com/dotnet/runtime:10.0@sha256:8c805532821f1cdea2cf3b74fd3e89dfd14e5de16c021af2d9e418377b0c5247
ARG SOURCE_REVISION=unknown
LABEL org.opencontainers.image.source="https://github.com/violetweather/Certael" \
      org.opencontainers.image.revision="$SOURCE_REVISION" \
      org.opencontainers.image.licenses="Apache-2.0"
WORKDIR /app
COPY --from=build /app .
COPY LICENSE /licenses/LICENSE
USER $APP_UID
ENTRYPOINT ["dotnet", "Certael.AnalyticsWorker.dll"]
