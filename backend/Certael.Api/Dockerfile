FROM mcr.microsoft.com/dotnet/sdk:10.0@sha256:ea8bde36c11b6e7eec2656d0e59101d4462f6bd630730f2c8201ed0572b295d5 AS build
WORKDIR /src
COPY . .
RUN dotnet publish backend/Certael.Api/Certael.Api.csproj -c Release -o /out
FROM mcr.microsoft.com/dotnet/aspnet:10.0@sha256:7644f992230d35cf230017189d4038c0ae0f7388b13f4f7ae1900a155bafb597
ARG SOURCE_REVISION=unknown
LABEL org.opencontainers.image.source="https://github.com/violetweather/Certael" \
      org.opencontainers.image.revision="$SOURCE_REVISION" \
      org.opencontainers.image.licenses="Apache-2.0"
WORKDIR /app
COPY --from=build /out .
COPY LICENSE /licenses/LICENSE
USER $APP_UID
EXPOSE 8080
ENTRYPOINT ["dotnet", "Certael.Api.dll"]
