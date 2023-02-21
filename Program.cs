using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace DNS_Bruteforce;

internal class Program
{
    static List<string>? subdomains;
    static List<string> validSubdomains = new();
    static DnsLookup lookup;
    static CancellationToken cancelToken;
    static string rootDomain = "stratussecurity.com";
    static int sentRequests = 0;
    static int processedCount = 0;
    static int maxConcurrency = 10000;
    static Stopwatch timer = new();
    static Socket udpSocket = new(SocketType.Dgram, ProtocolType.Udp);

    static async Task Main(string[] args)
    {
        // Get all the data
        subdomains = File.ReadAllLines("C:\\Users\\cojwa\\source\\repos\\TheENPT\\TheENPTer\\Configuration\\subdomains_small.txt").ToList();
        var resolvers = File.ReadAllLines("C:\\Users\\cojwa\\source\\repos\\TheENPT\\TheENPTer\\Configuration\\dns_resolvers.txt").ToList();
        var range = Enumerable.Range(0, subdomains.Count).ToList();

        var resolverEndpoints = new List<IPAddress>();
        foreach (var resolver in resolvers)
        {
            resolverEndpoints.Add(IPAddress.Parse(resolver));
        }
        lookup = new DnsLookup(resolverEndpoints.ToArray());

        // Get a cancel source that cancels when the user presses CTRL+C.
        var userExitSource = GetUserConsoleCancellationSource();
        cancelToken = userExitSource.Token;

        // Discard our socket when the user cancels.
        using var cancelReg = cancelToken.Register(udpSocket.Dispose);

        // Start a background task to receive the data
        var receiveTask = lookup.ReceiveAsync(udpSocket, cancelToken, ReceiveCallback);

        var stalePacketTask = lookup.ResendStaleQueries(cancelToken, ReceiveCallback);

        // Resolve the subdomains :D
        timer.Start();
        for (var i = 0; i < range.Count; i++)
        {
            if ((sentRequests - AllCount) < maxConcurrency)
            {
                await lookup.SendAsync($"{subdomains[i]}.{rootDomain}", udpSocket, cancelToken);
                sentRequests++;
            }
            else
            {
                await Task.Delay(1000);
                i--;
            }
        }

        try
        {
            while (!cancelToken.IsCancellationRequested)
            {
                await Task.Delay(1000);
                if (processedCount == subdomains.Count)
                {
                    if (!lookup.IsQueueEmpty())
                    {

                    }
                    userExitSource.Cancel();
                }
            }

            await stalePacketTask;
            await receiveTask;
        }
        catch (TaskCanceledException)
        {
            // This is planned, we're done :D
        }

        Console.WriteLine();
        foreach (var subdomain in validSubdomains)
        {
            Console.WriteLine($"Found: {subdomain}");
        }
        Console.WriteLine($"Took {timer.Elapsed.Seconds} seconds");
    }

    private static int ExistCount = 0;
    private static int ServFailCount = 0;
    private static int RefusedCount = 0;
    private static int ErrorCount = 0;
    private static int TimeoutCount = 0;
    private static int NotExistCount = 0;
    private static int NotImpCount = 0;
    private static int AllCount = 0;
    private static async Task ReceiveCallback(ushort id, DnsResult result, string dnsServer, string domain)
    {
        if(domain == "dradis.stratussecurity.com" || domain == "www.stratussecurity.com" || domain == "nessus.stratussecurity.com")
        {
            if(result != DnsResult.EXIST)
            {

            }
        }

        if (result == DnsResult.EXIST)
        {
            //validResults.Add($"{subdomains[i]}.{domain}");
            ExistCount++;
            Interlocked.Increment(ref processedCount);
            validSubdomains.Add(domain);
            //Console.WriteLine();
            //Console.WriteLine($":D | {id} | {domain}");
        }
        else if (result == DnsResult.SERVFAIL)
        {
            ServFailCount++;
            Interlocked.Increment(ref processedCount);
            // We don't retry these
        }
        else if (result == DnsResult.REFUSED)
        {
            RefusedCount++;
            Interlocked.Increment(ref processedCount);
            // We don't retry these
        }
        else if (result == DnsResult.ERROR)
        {
            ErrorCount++;
            await lookup.SendAsync(domain, udpSocket, cancelToken);
            Interlocked.Increment(ref sentRequests);
        }
        else if (result == DnsResult.TIME_OUT)
        {
            TimeoutCount++;
            await lookup.SendAsync(domain, udpSocket, cancelToken);
            Interlocked.Increment(ref sentRequests);
        }
        else if (result == DnsResult.NOT_EXIST)
        {
            NotExistCount++;
            Interlocked.Increment(ref processedCount);
            // This is fine
        }
        else if (result == DnsResult.NOT_IMP)
        {
            NotImpCount++;
            await lookup.SendAsync(domain, udpSocket, cancelToken);
            Interlocked.Increment(ref sentRequests);
        }
        else
        {
            throw new Exception("Unexcepted DNS result!");
        }

        AllCount++;
        var printOut = $"\rSent {sentRequests} | Received {AllCount} | Error: {ErrorCount} | Refused {RefusedCount} | ServFail {ServFailCount} | Timeout {TimeoutCount} | Not Implemented {NotImpCount} | Not Exist {NotExistCount} | Exist {ExistCount} | Total {processedCount}/{subdomains.Count}";
        if (timer.Elapsed.Seconds > 0 && AllCount > 0 && sentRequests > 0)
        {
            printOut += $" | {AllCount / timer.Elapsed.Seconds} received/s | {sentRequests / timer.Elapsed.Seconds} sent/s";
        }
        Console.Write(printOut + "  ");
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