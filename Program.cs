using System.Diagnostics;
using System.Linq;
using System.Net;

namespace DNS_Bruteforce;

internal class Program
{
    static string[]? subdomains;
    static DnsLookup? lookup;
    static CancellationToken cancelToken;
    static readonly string rootDomain = "stratussecurity.com";
    static readonly int maxConcurrency = 65535;
    static readonly Stopwatch timer = new();

    static async Task Main()
    {
        // Get all the data
        subdomains = File.ReadAllLines("C:\\Users\\cojwa\\source\\repos\\TheENPT\\TheENPTer\\Configuration\\subdomains.txt").Select(s => $"{s}.{rootDomain}").ToArray();
        var resolvers = File.ReadAllLines("C:\\Users\\cojwa\\source\\repos\\TheENPT\\TheENPTer\\Configuration\\dns_resolvers.txt").ToList();
        var range = Enumerable.Range(0, subdomains.Length).ToList();

        var resolverEndpoints = new IPAddress[resolvers.Count];
        for (var i = 0; i < resolvers.Count; i++)
        {
            resolverEndpoints[i] = IPAddress.Parse(resolvers[i]);
        }

        lookup = new DnsLookup(resolverEndpoints, subdomains, maxConcurrency);

        // Get a cancel source that cancels when the user presses CTRL+C.
        var userExitSource = GetUserConsoleCancellationSource();
        cancelToken = userExitSource.Token;

        timer.Start();
        var validSubs = await lookup.BruteForce(cancelToken, true);
        timer.Stop();

        Console.WriteLine();
        foreach (var subdomain in validSubs.Order())
        {
            Console.WriteLine($"Found: {subdomain}");
        }
        Console.WriteLine($"Took {timer.Elapsed.TotalSeconds} seconds");
    }

    private static CancellationTokenSource GetUserConsoleCancellationSource()
    {
        var cancellationSource = new CancellationTokenSource();

        Console.CancelKeyPress += (sender, args) =>
        {
            args.Cancel = true;
            cancellationSource.Cancel();
        };

        return cancellationSource;
    }
}