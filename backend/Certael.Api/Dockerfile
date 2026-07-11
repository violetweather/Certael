FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY . .
RUN dotnet publish backend/Certael.Api/Certael.Api.csproj -c Release -o /out
FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /out .
USER $APP_UID
EXPOSE 8080
ENTRYPOINT ["dotnet", "Certael.Api.dll"]
