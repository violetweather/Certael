FROM node:22.22.3-bookworm-slim@sha256:e21fc383b50d5347dc7a9f1cae45b8f4e2f0d39f7ade28e4eef7d2934522b752 AS console-build
WORKDIR /src/console
RUN corepack enable
COPY console/package.json console/pnpm-lock.yaml console/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY console/ ./
RUN pnpm run build

FROM mcr.microsoft.com/dotnet/sdk:10.0@sha256:ea8bde36c11b6e7eec2656d0e59101d4462f6bd630730f2c8201ed0572b295d5 AS build
WORKDIR /src
COPY . .
RUN dotnet publish backend/Certael.Console.Bff/Certael.Console.Bff.csproj -c Release -o /out -p:BuildConsole=false
COPY --from=console-build /src/console/dist /out/wwwroot
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
ENTRYPOINT ["dotnet", "Certael.Console.Bff.dll"]
