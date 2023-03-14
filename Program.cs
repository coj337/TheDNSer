using System.Diagnostics;

namespace DNS_Bruteforce;

internal class Program
{
    static readonly string rootDomain = "stratussecurity.com";
    static readonly Stopwatch timer = new();

    static async Task Main(string[] args)
    {
        if (args.Length < 2)
        {
            Console.WriteLine("Usage: TheDNS.exe <subdomains_file> <resolvers_file>");
            return;
        }

        if (!File.Exists(args[0]))
        {
            Console.WriteLine("Subdomain file does not exist.");
            return;
        }

        if (!File.Exists(args[1]))
        {
            Console.WriteLine("Resolvers file does not exist.");
            return;
        }

        // Get all the data
        var subdomains = File.ReadAllLines(args[0]).Select(s => $"{s}.{rootDomain}").ToArray();
        var resolvers = File.ReadAllLines(args[1]).ToArray();

        // Construct and run
        timer.Start();
        var lookup = new DnsLookup(resolvers, subdomains);
        var validSubs = await lookup.BruteForce(true);
        timer.Stop();

        // Write some final stats
        Console.WriteLine();
        foreach (var subdomain in validSubs.Order())
        {
            Console.WriteLine($"Found: {subdomain}");
        }
        Console.WriteLine($"Took {timer.Elapsed.TotalSeconds} seconds");
    }
}