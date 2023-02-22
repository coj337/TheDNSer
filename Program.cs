using System.Diagnostics;
using System.Net;

namespace DNS_Bruteforce;

internal class Program
{
    static List<string>? subdomains;
    static DnsLookup? lookup;
    static CancellationToken cancelToken;
    static readonly string rootDomain = "stratussecurity.com";
    //30k Subs, retry all -- 10k @ 86.75 sec | 20k @ 67.55456 sec
    //30k Subs, retry normal -- 10k @ 60.55 sec | 20k @ 52.4209015 sec | 37.3495173 sec
    //30k subs, retry normal, custom concurrency --  
    static readonly int maxConcurrency = 10000; //TODO: Make it keep the concurrency up by duping remaining hosts
    static readonly Stopwatch timer = new();

    static async Task Main()
    {
        // Get all the data
        subdomains = File.ReadAllLines("C:\\Users\\cojwa\\source\\repos\\TheENPT\\TheENPTer\\Configuration\\subdomains_small.txt").ToList();
        var resolvers = File.ReadAllLines("C:\\Users\\cojwa\\source\\repos\\TheENPT\\TheENPTer\\Configuration\\dns_resolvers.txt").ToList();
        var range = Enumerable.Range(0, subdomains.Count).ToList();

        var resolverEndpoints = new IPAddress[resolvers.Count];
        for (var i = 0; i < resolvers.Count; i++)
        {
            resolverEndpoints[i] = IPAddress.Parse(resolvers[i]);
        }
        lookup = new DnsLookup(resolverEndpoints, maxConcurrency);

        // Get a cancel source that cancels when the user presses CTRL+C.
        var userExitSource = GetUserConsoleCancellationSource();
        cancelToken = userExitSource.Token;

        // Start background tasks to send, receive and process the data
        var tasks = new List<Task>
        {
            lookup.StartReceivedProcessorAsync(cancelToken),
            lookup.StartSendProcessorAsync(cancelToken),
            lookup.ResendStaleQueries(cancelToken),
            PrintStats()
        };

        var receiveThread = new Thread(() => lookup.ProcessReceiveQueueAsync(cancelToken))
        {
            IsBackground = true
        };
        receiveThread.Start();

        // Resolve the subdomains :D
        timer.Start();
        for (var i = 0; i < range.Count; i++)
        {
            lookup.Send($"{subdomains[i]}.{rootDomain}");
        }
        
        try
        {
            while (!cancelToken.IsCancellationRequested)
            {
                await Task.Delay(1000);
                if (lookup.processedCount >= subdomains.Count && lookup.IsQueueEmpty())
                {
                    userExitSource.Cancel();
                }
            }

            await Task.WhenAll(tasks);
        }
        catch (OperationCanceledException)
        {
            // This is planned, we're done :D
            timer.Stop();
        }

        Console.WriteLine();
        foreach (var subdomain in lookup.validSubdomains)
        {
            Console.WriteLine($"Found: {subdomain}");
        }
        Console.WriteLine($"Took {timer.Elapsed.TotalSeconds} seconds");
    }

    private static async Task PrintStats()
    {
        while (!cancelToken.IsCancellationRequested)
        {
            await Task.Delay(1000);
            if (lookup != null)
            {
                var printOut = $"\rS_Pending {lookup.GetSendQueueSize()} | R_Pending {lookup.GetRetreiveQueueSize()} | Sent {lookup.sent} | Received {lookup.AllCount} | Error: {lookup.ErrorCount} | Refused {lookup.RefusedCount} | ServFail {lookup.ServFailCount} | Timeout {lookup.TimeoutCount} | Not Imp {lookup.NotImpCount} | Not Exist {lookup.NotExistCount} | Exist {lookup.ExistCount} | Total {lookup.processedCount}/{subdomains?.Count ?? 0}";
                if (timer.Elapsed.Seconds > 0 && lookup.AllCount > 0 && lookup.sent > 0)
                {
                    printOut += $" | {lookup.AllCount / timer.Elapsed.Seconds} received/s | {lookup.sent / timer.Elapsed.Seconds} sent/s";
                }
                Console.Write(printOut + "  ");
            }
        }
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