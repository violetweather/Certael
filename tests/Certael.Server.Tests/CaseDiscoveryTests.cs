using System.Collections.Immutable;
using Certael.Server.Actions;
using Certael.Server.Cases;
using Certael.Server.Evidence;

namespace Certael.Server.Tests;

public sealed class CaseDiscoveryTests
{
    [Fact]
    public async Task PaginatesFiltersAndSearchesOnlyNonSensitiveMetadata()
    {
        var clock = new MutableTimeProvider(new DateTimeOffset(2026, 7, 17, 12, 0, 0, TimeSpan.Zero));
        var store = new InMemoryCaseStore(clock);
        CaseSummary first = await Open(store, Bundle("player-1", "economy.circular-transfer",
            SignalFamily.EconomyAnomaly, clock.GetUtcNow()), "Economy transfer");
        clock.Advance(TimeSpan.FromMinutes(1));
        _ = await Open(store, Bundle("player-2", "protocol.sequence",
            SignalFamily.ProtocolViolation, clock.GetUtcNow()), "Sequence replay");
        clock.Advance(TimeSpan.FromMinutes(1));
        _ = await Open(store, Bundle("player-3", "economy.velocity",
            SignalFamily.EconomyAnomaly, clock.GetUtcNow()), "Velocity finding");

        CaseSummary? classified = await store.UpdateMetadataAsync("tenant", first.CaseId,
            "Economy", [
                new CaseMetadataValue("order_id", CaseMetadataType.Identifier, "order-123",
                    Searchable: true),
                new CaseMetadataValue("reference", CaseMetadataType.Identifier, "hidden-reference"),
                new CaseMetadataValue("internal_note", CaseMetadataType.Text, "secret-marker", Sensitive: true)
            ], "operator", "Classified investigation", first.Version,
            TestContext.Current.CancellationToken);
        Assert.NotNull(classified);

        CaseQueuePage firstPage = await store.SearchPageAsync(new CaseQueueQuery(
            "tenant", "prod", PageSize: 2), TestContext.Current.CancellationToken);
        Assert.Equal(2, firstPage.Items.Count);
        Assert.True(firstPage.HasMore);
        Assert.NotNull(firstPage.NextCursor);
        CaseQueuePage secondPage = await store.SearchPageAsync(new CaseQueueQuery(
            "tenant", "prod", Cursor: firstPage.NextCursor, PageSize: 2),
            TestContext.Current.CancellationToken);
        Assert.Single(secondPage.Items);
        Assert.Empty(firstPage.Items.Select(value => value.CaseId)
            .Intersect(secondPage.Items.Select(value => value.CaseId)));

        CaseQueuePage metadata = await store.SearchPageAsync(new CaseQueueQuery(
            "tenant", "prod", Search: "order-123"), TestContext.Current.CancellationToken);
        Assert.Single(metadata.Items);
        CaseQueuePage sensitive = await store.SearchPageAsync(new CaseQueueQuery(
            "tenant", "prod", Search: "secret-marker"), TestContext.Current.CancellationToken);
        Assert.Empty(sensitive.Items);
        CaseQueuePage nonSearchable = await store.SearchPageAsync(new CaseQueueQuery(
            "tenant", "prod", Search: "hidden-reference"), TestContext.Current.CancellationToken);
        Assert.Empty(nonSearchable.Items);
        CaseQueuePage rules = await store.SearchPageAsync(new CaseQueueQuery(
            "tenant", "prod", RuleId: "economy."), TestContext.Current.CancellationToken);
        Assert.Equal(2, rules.Items.Count);
        Assert.All(rules.Items, value => Assert.Contains(value.RuleIds ?? [],
            ruleId => ruleId.StartsWith("economy.", StringComparison.Ordinal)));
        Assert.All(rules.Items, value => Assert.Contains(SignalFamily.EconomyAnomaly,
            value.SignalFamilies ?? []));
        CaseQueuePage signals = await store.SearchPageAsync(new CaseQueueQuery(
            "tenant", "prod", SignalFamily: SignalFamily.ProtocolViolation),
            TestContext.Current.CancellationToken);
        Assert.Single(signals.Items);
        Assert.Equal("Economy", classified.Category);
    }

    [Fact]
    public async Task CaseSettingsAreScopedVersionedAndValidateSensitiveSearch()
    {
        var clock = new MutableTimeProvider(new DateTimeOffset(2026, 7, 17, 14, 0, 0, TimeSpan.Zero));
        var store = new InMemoryCaseSettingsStore(clock);
        var scope = new CaseSettingsScope("tenant", "game", "prod");
        CaseCategoryDefinition? created = await store.UpsertCategoryAsync(scope,
            new CaseCategoryDefinition("economy", "Economy", "Economy investigations",
                true, 10, 0, default), 0, "operator", "Create category",
            TestContext.Current.CancellationToken);
        Assert.NotNull(created);
        Assert.Equal(1, created.Version);

        CaseCategoryDefinition? conflict = await store.UpsertCategoryAsync(scope,
            created with { DisplayName = "Economy abuse" }, 0, "operator", "Stale update",
            TestContext.Current.CancellationToken);
        Assert.Null(conflict);

        CaseMetadataDefinition? metadata = await store.UpsertMetadataDefinitionAsync(scope,
            new CaseMetadataDefinition("transaction.kind", "Transaction kind",
                CaseMetadataType.Enumeration, ["trade", "reward"], false, true,
                false, true, 0, default), 0, "operator", "Create searchable field",
            TestContext.Current.CancellationToken);
        Assert.NotNull(metadata);
        Assert.Equal(1, metadata.Version);

        await Assert.ThrowsAsync<ArgumentException>(async () =>
            await store.UpsertMetadataDefinitionAsync(scope,
                metadata with { Key = "private.note", Sensitive = true, Searchable = true },
                0, "operator", "Invalid field", TestContext.Current.CancellationToken));

        CaseSettingsSnapshot snapshot = await store.GetAsync(scope,
            TestContext.Current.CancellationToken);
        Assert.Single(snapshot.Categories);
        Assert.Single(snapshot.MetadataDefinitions);
        CaseSettingsSnapshot isolated = await store.GetAsync(scope with { EnvironmentId = "dev" },
            TestContext.Current.CancellationToken);
        Assert.Empty(isolated.Categories);
        Assert.Empty(isolated.MetadataDefinitions);
    }

    [Fact]
    public async Task EvidenceCatalogPagesAndFiltersWithoutSearchingRawFields()
    {
        var store = new InMemoryEvidenceStore();
        DateTimeOffset now = new(2026, 7, 17, 15, 0, 0, TimeSpan.Zero);
        EvidenceBundle first = Bundle("player-1", "economy.circular-transfer",
            SignalFamily.EconomyAnomaly, now);
        EvidenceBundle second = Bundle("player-2", "protocol.sequence",
            SignalFamily.ProtocolViolation, now.AddMinutes(1));
        EvidenceBundle third = Bundle("player-3", "economy.velocity",
            SignalFamily.EconomyAnomaly, now.AddMinutes(2));
        await store.SaveAsync(first, TestContext.Current.CancellationToken);
        await store.SaveAsync(second, TestContext.Current.CancellationToken);
        await store.SaveAsync(third, TestContext.Current.CancellationToken);

        EvidenceSearchPage page = await store.SearchAsync(new EvidenceSearchQuery(
            "tenant", "prod", PageSize: 2), TestContext.Current.CancellationToken);
        Assert.Equal(2, page.Items.Count);
        Assert.True(page.HasMore);
        Assert.NotNull(page.NextCursor);
        EvidenceSearchPage next = await store.SearchAsync(new EvidenceSearchQuery(
            "tenant", "prod", Cursor: page.NextCursor, PageSize: 2),
            TestContext.Current.CancellationToken);
        Assert.Single(next.Items);
        Assert.Empty(page.Items.Select(value => value.VerdictId)
            .Intersect(next.Items.Select(value => value.VerdictId)));

        EvidenceSearchPage rule = await store.SearchAsync(new EvidenceSearchQuery(
            "tenant", "prod", RuleId: "economy."), TestContext.Current.CancellationToken);
        Assert.Equal(2, rule.Items.Count);
        EvidenceSearchPage signal = await store.SearchAsync(new EvidenceSearchQuery(
            "tenant", "prod", SignalFamily: SignalFamily.ProtocolViolation),
            TestContext.Current.CancellationToken);
        Assert.Single(signal.Items);
        EvidenceSearchPage text = await store.SearchAsync(new EvidenceSearchQuery(
            "tenant", "prod", Search: "player-3"), TestContext.Current.CancellationToken);
        Assert.Single(text.Items);
    }

    [Fact]
    public void CursorRejectsMalformedAndOversizedValues()
    {
        Assert.Throws<ArgumentException>(() => CaseQueueCursorCodec.Decode("not-base64"));
        Assert.Throws<ArgumentException>(() => CaseQueueCursorCodec.Decode(new string('a', 513)));
    }

    private static async Task<CaseSummary> Open(InMemoryCaseStore store, EvidenceBundle bundle,
        string title) => await store.OpenOrUpdateAsync(bundle, title, "Explainable finding",
            "analytics-worker", TimeSpan.FromHours(24), TestContext.Current.CancellationToken)
            ?? throw new InvalidOperationException("Case did not open.");

    private static EvidenceBundle Bundle(string player, string rule, SignalFamily signal,
        DateTimeOffset now)
    {
        Guid findingId = Guid.NewGuid();
        var finding = new Finding(findingId, "tenant", "game", "prod", Guid.NewGuid().ToString(),
            player, rule, "1", new byte[32], Guid.NewGuid(), signal, FindingTrust.Authoritative,
            20, 0.9, now, ImmutableArray.Create(
                new EvidenceField("source", "test", Provenance.CertaelDerived)));
        var verdict = new Verdict(Guid.NewGuid(), "tenant", "game", "prod", finding.SessionId,
            player, 20, 0.9, VerdictRecommendation.RecommendManualReview,
            ImmutableArray.Create(findingId), ImmutableArray.Create("1"), now);
        return new EvidenceBundle(verdict, ImmutableArray.Create(finding), new byte[32],
            "policy", "1");
    }

    private sealed class MutableTimeProvider(DateTimeOffset current) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => current;
        public void Advance(TimeSpan duration) => current += duration;
    }
}
