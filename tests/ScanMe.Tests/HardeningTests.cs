using ScanMe.Core.Hardening;

namespace ScanMe.Tests;

public class HardeningTests
{
    [Fact]
    public void Catalog_HasUniqueIds_AndExplanations()
    {
        var all = HardeningCatalog.All;
        Assert.Equal(all.Count, all.Select(i => i.Id).Distinct().Count());
        Assert.All(all, i =>
        {
            Assert.False(string.IsNullOrWhiteSpace(i.Plain));
            Assert.False(string.IsNullOrWhiteSpace(i.Protects));
        });
    }

    [Fact]
    public void AsrRules_HaveValidGuids()
    {
        foreach (var item in HardeningCatalog.All.Where(i => i.Id.StartsWith("asr:")))
            Assert.True(Guid.TryParse(item.Id[4..], out _), item.Id);
    }

    [Fact]
    public void DeveloperSensitiveRules_AreNotForcedOn()
    {
        // Regeln, die laut Hinweis Entwicklerwerkzeuge blockieren koennen, duerfen nicht ungefragt scharf geschaltet werden.
        var sensitive = new[] { "asr:5beb7efe-fd9a-4556-801d-275e5ffc04cc", "asr:c1db55ab-c21a-4637-bb3f-a12568109d35",
                                "asr:01443614-cd74-433a-b99e-2ecdc07bfc25", "asr:d1e49aac-8f56-4280-b9ba-993a6d77406c", "def:cfa" };
        foreach (var id in sensitive)
        {
            var item = HardeningCatalog.All.Single(i => i.Id == id);
            Assert.NotEqual(HardeningMode.On, item.Recommended);
            Assert.NotNull(item.DevNote);
        }
    }

    [Theory]
    [InlineData(HardeningState.On, HardeningMode.Audit, true)]
    [InlineData(HardeningState.Audit, HardeningMode.On, false)]
    [InlineData(HardeningState.Off, HardeningMode.Audit, false)]
    [InlineData(HardeningState.Audit, HardeningMode.Audit, true)]
    public void Satisfies_TreatsStricterAsSufficient(HardeningState state, HardeningMode wanted, bool expected) =>
        Assert.Equal(expected, HardeningService.Satisfies(state, wanted));
}
