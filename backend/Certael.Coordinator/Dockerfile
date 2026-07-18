FROM mcr.microsoft.com/dotnet/sdk:10.0@sha256:ed034a8bf0b24ded0cbbac07e17825d8e9ebfe21e308191d0f7421eaf5ad4664 AS build
WORKDIR /src
COPY . .
RUN dotnet publish backend/Certael.Coordinator/Certael.Coordinator.csproj -c Release -o /out
FROM mcr.microsoft.com/dotnet/aspnet:10.0@sha256:1fa23fc4872d95fd71c2833ebe65d7e84a43b2d51a31d119516852f13d9505a7
ARG SOURCE_REVISION=unknown
LABEL org.opencontainers.image.source="https://github.com/violetweather/Certael" org.opencontainers.image.revision="$SOURCE_REVISION" org.opencontainers.image.licenses="Apache-2.0"
WORKDIR /app
COPY --from=build /out .
COPY LICENSE /licenses/LICENSE
USER $APP_UID
ENTRYPOINT ["dotnet", "Certael.Coordinator.dll"]
