namespace Strongthium.HostDossier.Tests;

public class NameTests
{
    [Theory]
    [InlineData("example.com", "example.com")]
    [InlineData("  EXAMPLE.com. ", "example.com")]
    [InlineData("https://www.example.com:8443/path?x=1", "www.example.com")]
    [InlineData("someone@example.com", "example.com")]
    [InlineData("bücher.example", "xn--bcher-kva.example")]
    public void Reads_names(string input, string expected)
    {
        var target = Names.ParseTarget(input, out _);
        Assert.NotNull(target);
        Assert.Equal(TargetKind.Domain, target.Kind);
        Assert.Equal(expected, target.Name);
    }

    [Theory]
    [InlineData("192.0.2.1", "192.0.2.1")]
    [InlineData("[2001:db8::1]:443", "2001:db8::1")]
    [InlineData("https://[2001:db8::1]/", "2001:db8::1")]
    [InlineData("2001:DB8::1", "2001:db8::1")]
    public void Reads_addresses(string input, string expected)
    {
        var target = Names.ParseTarget(input, out _);
        Assert.NotNull(target);
        Assert.Equal(TargetKind.Address, target.Kind);
        Assert.Equal(expected, target.Name);
    }

    [Theory]
    [InlineData("")]
    [InlineData("localhost")]
    [InlineData("not a name.example")]
    public void Refuses_what_is_neither(string input)
    {
        Assert.Null(Names.ParseTarget(input, out var problem));
        Assert.NotNull(problem);
    }

    [Theory]
    [InlineData("www.example.com", "example.com")]
    [InlineData("a.b.example.co.uk", "example.co.uk")]
    [InlineData("example.co.uk", "example.co.uk")]
    [InlineData("co.uk", null)]
    [InlineData("com", null)]
    [InlineData("foo.bar.ck", "foo.bar.ck")] // *.ck: bar.ck is itself a suffix.
    [InlineData("www.ck", "www.ck")] // !www.ck: the exception to it.
    [InlineData("a.www.ck", "www.ck")]
    [InlineData("host.invalidtld", "host.invalidtld")] // Not listed: its last label is treated as a suffix.
    public void Finds_the_registrable_part(string name, string? expected) => Assert.Equal(expected, Names.RegistrableDomain(name));

    [Theory]
    [InlineData("192.0.2.1", "1.2.0.192")]
    [InlineData("2001:db8::1", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2")]
    public void Reverses_addresses(string ip, string expected) => Assert.Equal(expected, Names.ReversedLabels(ip));

    [Theory]
    [InlineData("10.1.2.3", true)]
    [InlineData("192.168.1.1", true)]
    [InlineData("172.20.0.1", true)]
    [InlineData("100.64.0.1", true)]
    [InlineData("127.0.0.1", true)]
    [InlineData("203.0.113.5", true)]
    [InlineData("fe80::1", true)]
    [InlineData("fd00::1", true)]
    [InlineData("8.8.8.8", false)]
    [InlineData("172.32.0.1", false)]
    [InlineData("2606:4700::1111", false)]
    public void Knows_special_addresses(string ip, bool special) => Assert.Equal(special, Names.SpecialUse(ip) is not null);

    [Fact]
    public void Networks_are_masked_and_tested()
    {
        Assert.True(Names.TryParseNetwork("192.0.2.77/24", out var network, out var prefix));
        Assert.Equal("192.0.2.0/24", Names.FormatNetwork(network, prefix));
        Assert.True(Names.NetworkContains("192.0.2.0/24", "192.0.2.200"));
        Assert.False(Names.NetworkContains("192.0.2.0/24", "192.0.3.1"));
        Assert.False(Names.NetworkContains("192.0.2.0/24", "2001:db8::1"));
        Assert.True(Names.NetworkContains("2001:db8::/32", "2001:db8:1::1"));
        Assert.False(Names.TryParseNetwork("192.0.2.0/33", out _, out _));
        Assert.Equal(256, Names.AddressCount("192.0.2.0/24"));
        Assert.Equal(1, Names.AddressCount("192.0.2.1"));
    }

    [Fact]
    public void A_small_network_is_listed_whole()
    {
        var addresses = Names.SampleAddresses("192.0.2.0/30", 8);
        Assert.Equal(["192.0.2.0", "192.0.2.1", "192.0.2.2", "192.0.2.3"], addresses);
    }

    [Fact]
    public void A_big_network_is_sampled_inside_itself()
    {
        var addresses = Names.SampleAddresses("10.0.0.0/8", 8);
        Assert.Equal(8, addresses.Count);
        Assert.Equal(8, addresses.Distinct().Count());
        Assert.All(addresses, a => Assert.True(Names.NetworkContains("10.0.0.0/8", a)));

        var six = Names.SampleAddresses("2001:db8::/32", 4);
        Assert.Equal(4, six.Count);
        Assert.All(six, a => Assert.True(Names.NetworkContains("2001:db8::/32", a)));
    }
}
