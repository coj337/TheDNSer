using System.Diagnostics;
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
    static readonly TimeSpan queryTimeout = TimeSpan.FromSeconds(1);

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

        // Start background tasks to send, receive and process the data
        var tasks = new List<Task>
        {
            lookup.StartReceivedProcessorAsync(cancelToken),
            lookup.StartSendProcessorAsync(cancelToken),
            lookup.StartSendQueuerAsync(cancelToken),
            PrintStats()
        };

        var receiveThread = new Thread(() => lookup.ProcessReceiveQueueAsync(cancelToken))
        {
            IsBackground = true
        };
        receiveThread.Start();
        
        try
        {
            await Task.WhenAll(tasks);
        }
        catch (OperationCanceledException)
        {
            // This is planned, we're done :D
        }
        timer.Stop();

        Console.WriteLine();
        foreach (var subdomain in lookup.validSubdomains.Order())
        {
            Console.WriteLine($"Found: {subdomain}");
        }
        Console.WriteLine($"Took {timer.Elapsed.TotalSeconds} seconds");
    }

    private static async Task PrintStats()
    {
        while (!cancelToken.IsCancellationRequested && !(lookup?.IsFinished() ?? false))
        {
            await Task.Delay(1000);
            if (lookup != null)
            {
                var printOut = $"\rS_Pending {lookup.GetSendQueueSize()} | R_Pending {lookup.GetRetrieveQueueSize()} | S {lookup.sentCount} | R {lookup.AllCount} | Err: {lookup.ErrorCount} | Refuse {lookup.RefusedCount} | ServFail {lookup.ServFailCount} | Timeout {lookup.TimeoutCount} | Not Imp {lookup.NotImpCount} | Not Exist {lookup.NotExistCount} | Exist {lookup.ExistCount} | Total {lookup.processedCount}/{subdomains?.Length ?? 0}";
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