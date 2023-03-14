﻿using DNS_Bruteforcer;
using System.Diagnostics;

namespace TheDNSer;

internal class Program
{
    static readonly string rootDomain = "stratussecurity.com";
    static readonly Stopwatch timer = new();

    static async Task Main(string[] args)
    {
        if (args.Length < 3)
        {
            Console.WriteLine("Usage: TheDNS.exe rootDomain.com <subdomains_file> <resolvers_file>");
            return;
        }

        if (string.IsNullOrEmpty(args[0]) || args[0].Contains(':'))
        {
            Console.WriteLine("Root domain is invalid.");
            return;
        }

        if (!File.Exists(args[1]))
        {
            Console.WriteLine("Subdomain file does not exist.");
            return;
        }

        if (!File.Exists(args[2]))
        {
            Console.WriteLine("Resolvers file does not exist.");
            return;
        }

        // Get all the data
        var subdomains = File.ReadAllLines(args[1]).Select(s => $"{s}.{args[0]}").ToArray();
        var resolvers = File.ReadAllLines(args[2]).ToArray();

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