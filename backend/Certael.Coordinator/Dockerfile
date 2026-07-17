FROM mcr.microsoft.com/dotnet/sdk:10.0@sha256:ea8bde36c11b6e7eec2656d0e59101d4462f6bd630730f2c8201ed0572b295d5 AS build
WORKDIR /src
COPY . .
RUN dotnet publish backend/Certael.Coordinator/Certael.Coordinator.csproj -c Release -o /out
FROM mcr.microsoft.com/dotnet/aspnet:10.0@sha256:5249e949eab7317fc97a29d06f6019a32f0be56ad53fb6f73e35824edfae8a57
ARG SOURCE_REVISION=unknown
LABEL org.opencontainers.image.source="https://github.com/violetweather/Certael" org.opencontainers.image.revision="$SOURCE_REVISION" org.opencontainers.image.licenses="Apache-2.0"
WORKDIR /app
COPY --from=build /out .
COPY LICENSE /licenses/LICENSE
USER $APP_UID
ENTRYPOINT ["dotnet", "Certael.Coordinator.dll"]
