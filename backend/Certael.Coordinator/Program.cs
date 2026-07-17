using System.Reflection;
using System.Security.Cryptography;
using Certael.Coordinator;
using Certael.Server.Sessions;
using Npgsql;

WebApplicationBuilder builder=WebApplication.CreateBuilder(args);
string connection=builder.Configuration.GetConnectionString("ControlPostgres")??throw new InvalidOperationException("ConnectionStrings:ControlPostgres is required.");
builder.Services.AddSingleton(NpgsqlDataSource.Create(connection));builder.Services.AddSingleton(TimeProvider.System);builder.Services.AddSingleton<CoordinatorStore>();
string signingKeyId=builder.Configuration["Coordinator:SigningKeyId"]??throw new InvalidOperationException("Coordinator:SigningKeyId is required.");
string signingKeyValue=builder.Configuration["Coordinator:SigningPrivateKeyPkcs8Base64"]??throw new InvalidOperationException("Coordinator:SigningPrivateKeyPkcs8Base64 is required.");
ECDsa signingKey=ECDsa.Create();signingKey.ImportPkcs8PrivateKey(Convert.FromBase64String(signingKeyValue),out _);
builder.Services.AddSingleton(signingKey);builder.Services.AddSingleton(new RegionTransferGrantSigner(signingKey,signingKeyId));
WebApplication app=builder.Build();
await ApplyMigration(app.Services.GetRequiredService<NpgsqlDataSource>());
app.MapGet("/healthz",()=>Results.Ok(new{status="ok"}));
app.MapPost("/v1/leases/acquire",async(AcquireRequest request,CoordinatorStore store,CancellationToken ct)=>
    await store.AcquireAsync(request.TenantId,request.GameId,request.EnvironmentId,request.MatchId,request.Region,request.ServerId,request.Force,request.Actor,ct) is { } lease?Results.Ok(lease):Results.Conflict(new{reason="MATCH_OWNED"}));
app.MapPost("/v1/leases/renew",async(MatchLease lease,CoordinatorStore store,CancellationToken ct)=>await store.RenewAsync(lease,ct)?Results.NoContent():Results.Conflict(new{reason="STALE_FENCING_EPOCH"}));
app.MapPost("/v1/leases/release",async(ReleaseRequest request,CoordinatorStore store,CancellationToken ct)=>await store.ReleaseAsync(request.Lease,request.Actor,ct)?Results.NoContent():Results.Conflict(new{reason="STALE_FENCING_EPOCH"}));
app.MapPost("/v1/transfers",async(TransferRequest request,CoordinatorStore store,RegionTransferGrantSigner signer,TimeProvider clock,CancellationToken ct)=>{if(!await store.IsCurrentOwnerAsync(request.Lease,ct))return Results.Conflict(new{reason="STALE_FENCING_EPOCH"});DateTimeOffset now=clock.GetUtcNow();var grant=new RegionTransferGrantV1(Guid.NewGuid(),request.Lease.TenantId,request.Lease.GameId,request.Lease.EnvironmentId,request.Lease.MatchId,request.PlayerSubject,request.Lease.OwnerRegion,request.DestinationRegion,request.Lease.FencingEpoch,RandomNumberGenerator.GetBytes(32),now,now.AddSeconds(60));await store.RecordGrantAsync(grant,ct);return Results.Ok(signer.Sign(grant));});
app.MapPost("/v1/transfers/redeem",async(RedeemRequest request,CoordinatorStore store,ECDsa key,TimeProvider clock,CancellationToken ct)=>{RegionTransferGrantV1 grant;try{if(request.Grant.KeyId!=signingKeyId)throw new RegionTransferGrantException("Unknown signing key.");grant=RegionTransferGrantSigner.Verify(request.Grant,new Dictionary<string,ECDsa>{{signingKeyId,key}},clock.GetUtcNow());}catch(RegionTransferGrantException){return Results.BadRequest(new{reason="INVALID_TRANSFER_GRANT"});}return await store.RedeemAsync(grant,request.ServerId,ct)?Results.Ok(new{freshSessionsRequired=true}):Results.Conflict(new{reason="TRANSFER_NOT_REDEEMABLE"});});
await app.RunAsync();
static async Task ApplyMigration(NpgsqlDataSource source){await using Stream stream=Assembly.GetExecutingAssembly().GetManifestResourceStream("Certael.Coordinator.Migrations.001_control.sql")??throw new InvalidOperationException("Missing migration.");using var reader=new StreamReader(stream);await using NpgsqlConnection c=await source.OpenConnectionAsync();await using var command=new NpgsqlCommand(await reader.ReadToEndAsync(),c);await command.ExecuteNonQueryAsync();}
public sealed record AcquireRequest(string TenantId,string GameId,string EnvironmentId,string MatchId,string Region,string ServerId,bool Force,string Actor);
public sealed record ReleaseRequest(MatchLease Lease,string Actor);
public sealed record TransferRequest(MatchLease Lease,string PlayerSubject,string DestinationRegion);
public sealed record RedeemRequest(SignedRegionTransferGrant Grant,string ServerId);
