using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace DNS_Bruteforcer;

public class DnsLookup
{
    private const int DNS_PORT = 53;
    private const int PACKET_SIZE = 512;
    private const int TIMEOUT_MS = 500;

    private static readonly IPEndPoint _blankEndpoint = new(IPAddress.Any, 0);
    private readonly IPAddress[] _dnsServers;
    private readonly IPEndPoint _sendEndpoint;
    private int _lastUsedDnsServerIndex;
    private readonly string[] _subdomains;
    private int _currentSubdomainIndex;
    private readonly QueryInfo[] _queryInfos;
    private readonly object[] _queryLocks; // An array of locks used to keep queries thread-safe
    private readonly Socket udpSocket;

    // An array that matches the indexes in _queryInfos to store unsent requests and avoid heap allocations
    private readonly Memory<byte>[] _pendingSends;
    private int _pendingSendSize = 0; // Track the size manually to avoid iterations in hot paths

    // Use a circular buffer instead of Queue<T> to avoid heap allocations
    private readonly Memory<byte>[] _pendingReceives;
    private int _pendingReceivesStart = 0;
    private int _pendingReceivesEnd = 0;

    // Track finished domains
    private readonly HashSet<string> _completedDomains;

    // Store our results
    public readonly ConcurrentBag<string> validSubdomains = new();

    public DnsLookup(string[] dnsServers, string[] subdomains, int maxConcurrency = 65535)
    {
        if(maxConcurrency > 65535)
        {
            throw new Exception("Exception: Max concurrency can't be above 65535.");
        }

        // Translate DNS servers
        var resolverEndpoints = new IPAddress[dnsServers.Length];
        for (var i = 0; i < dnsServers.Length; i++)
        {
            resolverEndpoints[i] = IPAddress.Parse(dnsServers[i]);
        }
        
        // Set up all the things
        _subdomains = subdomains;
        _completedDomains = new HashSet<string>(subdomains.Length);
        _pendingReceives = new Memory<byte>[maxConcurrency];
        _pendingSends = new Memory<byte>[maxConcurrency];
        _queryInfos = new QueryInfo[maxConcurrency];
        _queryLocks = new object[maxConcurrency];
        for (int i = 0; i < _queryLocks.Length; i++)
        {
            _queryLocks[i] = new object();
        }

        _dnsServers = resolverEndpoints;
        _sendEndpoint = new IPEndPoint(resolverEndpoints[0], DNS_PORT);
        udpSocket = new(SocketType.Dgram, ProtocolType.Udp);
    }

    public async Task<string[]> BruteForce(bool printSimpleStats = false, bool printAdvancedStats = false, CancellationToken cancelToken = default)
    {
        // Start background tasks to send, receive and process the data
        var tasks = new List<Task>
        {
            StartReceivedProcessorAsync(cancelToken),
            StartSendProcessorAsync(cancelToken),
            StartSendQueuerAsync(cancelToken),
        };
        if (printSimpleStats)
        {
            tasks.Add(PrintSimpleStats(cancelToken));
        }
        else if (printAdvancedStats)
        {
            tasks.Add(PrintAdvancedStats(cancelToken));
        }

        // The receive task gets an explicit thread to ensure lowest drop rate
        var receiveThread = new Thread(async () => await ProcessReceiveQueueAsync(cancelToken))
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

        return validSubdomains.ToArray();
    }

    public async Task StartSendQueuerAsync(CancellationToken cancelToken)
    {
        // Loop through all current, unfinished domains forever.
        // Note that this is intended to requeue still running domains because they can time out and we want max concurrency
        while (!cancelToken.IsCancellationRequested && !IsFinished())
        {
            for (var i = 0; i < _queryInfos.Length && !IsFinished(); i++)
            {
                if (_queryInfos[i].State != QueryState.NotStarted)
                {
                    // Check for timed out requests, if timed out remove it from the running count
                    if (_queryInfos[i].State == QueryState.Running && _queryInfos[i].StartTime < DateTime.UtcNow.AddMilliseconds(TIMEOUT_MS * -1))
                    {
                        // If we get a little racey, reset this request
                        lock (_queryLocks[i])
                        {
                            if (_completedDomains.Contains(_queryInfos[i].Hostname))
                            {
                                // Reset it, we're already done :D
                                _pendingSends[i] = default;
                                _queryInfos[i].State = QueryState.NotStarted;
                                continue;
                            }

                            Interlocked.Increment(ref TimeoutCount);
                            _queryInfos[i].State = QueryState.TimedOut;
                        }
                    }
                    else
                    {
                        await Task.Delay(10, cancelToken);
                        continue;
                    }
                }

                lock (_queryLocks[i])
                {
                    if (_queryInfos[i].State != QueryState.NotStarted && _queryInfos[i].State != QueryState.TimedOut) // Degub
                    {
                        throw new Exception("We shouldn't ever be here >:(");
                    }

                    // If we get here, it's time for a new request (unless it's timed out, then try again)
                    if (_queryInfos[i].State == QueryState.NotStarted)
                    {
                        _queryInfos[i].Hostname = _subdomains[_currentSubdomainIndex];
                        _currentSubdomainIndex = (_currentSubdomainIndex + 1) % _subdomains.Length;
                    }

                    // We tried to redo a domain?
                    if (_completedDomains.Contains(_queryInfos[i].Hostname))
                    {
                        continue;
                    }

                    // Stats 💯💯💯
                    Interlocked.Increment(ref submitted);

                    // Domain parts are split in the domain bytes so we need to add an extra spot for each part
                    var domainParts = _queryInfos[i].Hostname.Count(c => c == '.') + 1;

                    // Taking advantage of pre-pinned memory here using the .NET 5 POH (pinned object heap).
                    byte[] buffer = GC.AllocateArray<byte>(12 + _queryInfos[i].Hostname.Length + 4 + domainParts, pinned: true);
                    Memory<byte> bufferMem = buffer.AsMemory();

                    // Put request data in the buffer
                    BuildQueryMessage(_queryInfos[i].Hostname, bufferMem.Span);

                    // Write the ID based on the position in the array
                    BinaryPrimitives.WriteUInt16BigEndian(buffer, (ushort)i);

                    // Store query info
                    _queryInfos[i].State = QueryState.Queued;
                    _pendingSends[i] = bufferMem;
                    Interlocked.Increment(ref _pendingSendSize);
                }
            }
        }
    }

    public async Task StartSendProcessorAsync(CancellationToken cancelToken)
    {
        while (!cancelToken.IsCancellationRequested && !IsFinished())
        {
            // Sacrificing a little CPU to handle this as a plain array
            // Loop all the pending sends elements, the index represents the same index as a _queryInfos object
            for (var i = 0; i < _pendingSends.Length; i++)
            {
                // Make sure we have a real item and we're not breaking concurrency rules
                if (_pendingSends[i].Length > 0)
                {
                    lock (_queryLocks[i])
                    {
                        // If we get a little racey, reset this request
                        if (_completedDomains.Contains(_queryInfos[i].Hostname))
                        {
                            // Let it time out, we're already done :D
                            _pendingSends[i] = default;
                            _queryInfos[i].State = QueryState.NotStarted;
                            continue;
                        }

                        // Send it™️
                        _lastUsedDnsServerIndex = (_lastUsedDnsServerIndex + 1) % _dnsServers.Length;
                        _sendEndpoint.Address = _dnsServers[_lastUsedDnsServerIndex];
                        udpSocket.SendTo(_pendingSends[i].Span, SocketFlags.None, _sendEndpoint);

                        // Mark it as running
                        _queryInfos[i].StartTime = DateTime.UtcNow;
                        _queryInfos[i].State = QueryState.Running;
                        Interlocked.Increment(ref sentCount);

                        // Reset the memory back and track stats
                        _pendingSends[i] = default;
                        Interlocked.Decrement(ref _pendingSendSize);
                    }
                }
            }

            // If we don't have much concurrency left or there's nothing in queue, wait so the CPU can be chill
            if (_pendingSendSize == 0)
            {
                await Task.Delay(1000, cancelToken);
            }
        }
    }

    public async Task ProcessReceiveQueueAsync(CancellationToken cancelToken)
    {
        if (!udpSocket.IsBound)
        {
            udpSocket.Bind(_blankEndpoint);
        }

        while (!cancelToken.IsCancellationRequested && !IsFinished())
        {
            // Use pre-pinned memory using the .NET5 POH (pinned object heap).
            byte[] buffer = GC.AllocateArray<byte>(PACKET_SIZE, pinned: true);
            Memory<byte> bufferMem = buffer.AsMemory();

            var result = await udpSocket.ReceiveAsync(bufferMem, SocketFlags.None, cancelToken);

            var nextEnd = (_pendingReceivesEnd + 1) % _pendingReceives.Length;
            if (nextEnd != _pendingReceivesStart)
            {
                _pendingReceives[_pendingReceivesEnd] = bufferMem[..result];
                _pendingReceivesEnd = nextEnd;
                queued++;
            }
            else
            {
                throw new Exception("Receive buffer full! Dropping packets :(");
            }
        }
    }

    public bool IsFinished()
    {
        return processedCount >= _subdomains.Length;
    }

    public bool IsQueueEmpty()
    {
        return _queryInfos.All(q => q.State == QueryState.NotStarted);
    }

    public async Task StartReceivedProcessorAsync(CancellationToken cancelToken)
    {
        while (!cancelToken.IsCancellationRequested && !IsFinished())
        {
            if (GetRetrieveQueueSize() > 0)
            {
                // Effectively `var currentItem = Queue<T>.Dequeue()`
                var currentItem = _pendingReceives[_pendingReceivesStart];

                ParseResponseMessage(currentItem);
                _pendingReceives[_pendingReceivesStart] = default;

                _pendingReceivesStart = (_pendingReceivesStart + 1) % _pendingReceives.Length;
            }
            else
            {
                await Task.Delay(1000, cancelToken); // Wait if we're waiting for more packets
            }
        }
    }

    private void BuildQueryMessage(string domainName, Span<byte> buffer)
    {
        // Note: We skip the first two bytes (query ID) here and do it in the calling function
        var domainNameBytes = BuildDomainNameBytes(domainName, buffer[12..]);

        if (buffer.Length != 12 + domainNameBytes + 4)
        {
            throw new ArgumentException($"Buffer is the wrong size to hold the DNS query message. Needs {12 + domainNameBytes + 4} but has {buffer.Length} bytes.");
        }

        // Build the DNS header
        BinaryPrimitives.WriteUInt16BigEndian(buffer[2..], 0x0100); // QR = 0 (query), OPCODE = 0 (standard query), AA = 0, TC = 0, RD = 1 (recursion desired)
        BinaryPrimitives.WriteUInt16BigEndian(buffer[4..], 0x0001); // RA = 0, Z = 0, RCODE = 0, QDCOUNT = 1
        BinaryPrimitives.WriteUInt16BigEndian(buffer[6..], 0x0000); // ANCOUNT = 0
        BinaryPrimitives.WriteUInt16BigEndian(buffer[8..], 0x0000); // NSCOUNT = 0
        BinaryPrimitives.WriteUInt16BigEndian(buffer[10..], 0x0000); // ARCOUNT = 0

        // Build the DNS query
        BinaryPrimitives.WriteUInt16BigEndian(buffer[(12 + domainNameBytes)..], 0x0100); // QTYPE = A (host address)
        BinaryPrimitives.WriteUInt16BigEndian(buffer[(12 + domainNameBytes + 2)..], 0x0100); // QCLASS = IN (internet)
    }

    private int BuildDomainNameBytes(string domainName, Span<byte> buffer)
    {
        var domainNameParts = domainName.Split('.');
        int index = 0;
        foreach (var domainNamePart in domainNameParts)
        {
            buffer[index++] = (byte)domainNamePart.Length;
            System.Text.Encoding.ASCII.GetBytes(domainNamePart, buffer[index..]);
            index += domainNamePart.Length;
        }
        return domainName.Length + domainNameParts.Length; // Let the caller know how many bytes were written
    }

    private void ParseResponseMessage(ReadOnlyMemory<byte> responseMessage)
    {
        DnsResult result;
        var domainName = "";
        if (responseMessage.Length < 12)
        {
            // Invalid message, ignore
            return;
        }

        // Parse the DNS header
        var id = (ushort)((responseMessage.Span[0] << 8) | responseMessage.Span[1]);
        var flags = (responseMessage.Span[2] << 8) | responseMessage.Span[3];
        var responseCode = flags & 0x0F;
        if (responseCode != 0)
        {
            // These mean something got weird so we should try another server
            if (responseCode == 2)
            {
                result = DnsResult.SERVFAIL;
            }
            else if (responseCode == 3)
            {
                result = DnsResult.NOT_EXIST;
            }
            else if(responseCode == 4)
            {
                result = DnsResult.NOT_IMP;
            }
            else if (responseCode == 5)
            {
                result = DnsResult.REFUSED;
            }
            else
            {
                result = DnsResult.ERROR;
            }
            // 0 - NOERROR
            // 1 - FORMERR (DNS Query Format Error)
            // 2 - SERVFAIL (Server failed to complete the DNS request)
            // 3 - NXDOMAIN (Domain name does not exist.)
            // 4 - NOTIMP (Function not implemented) - This is sometimes used instead of 3
            // 5 - REFUSED (The server refused to answer for the query)
            // 6 - YXDOMAIN (Name that should not exist, does exist)
            // 7 - XRRSET (RRset that should not exist, does exist)
            // 8 - NOTAUTH (Server not authoritative for the zone)
            // 9 - NOTZONE (Name not in zone)
        }
        else
        {
            var answerCount = (responseMessage.Span[6] << 8) | responseMessage.Span[7];
            if (answerCount == 0)
            {
                // No A record
                result = DnsResult.NOT_EXIST;
            }
            else
            {
                result = DnsResult.EXIST;

                // Extract the domain name from the question section
                var questionSection = responseMessage[12..];
                int offset = 0;
                while (questionSection.Span[offset] != 0)
                {
                    if ((questionSection.Span[offset] & 0xC0) == 0xC0)
                    {
                        break;
                    }
                    var labelLength = questionSection.Span[offset];
                    domainName += Encoding.UTF8.GetString(questionSection.Slice(offset + 1, labelLength).ToArray()) + ".";
                    offset += labelLength + 1;
                }
                domainName = domainName.TrimEnd('.');
            }
        }

        // Process this boi
        ProcessStats(id, result, domainName);
    }

    public int GetSendQueueSize()
    {
        return _pendingSendSize;
    }

    public int GetRetrieveQueueSize()
    {
        return (_pendingReceivesEnd - _pendingReceivesStart + _pendingReceives.Length) % _pendingReceives.Length;
    }

    public int ExistCount = 0;
    public int ServFailCount = 0;
    public int RefusedCount = 0;
    public int ErrorCount = 0;
    public int TimeoutCount = 0;
    public int NotExistCount = 0;
    public int NotImpCount = 0;
    public int AllCount = 0;
    public int processedCount = 0;
    public int queued = 0;
    public int sentCount = 0;
    public int submitted = 0;
    private void ProcessStats(ushort id, DnsResult result, string resDomain)
    {
        if(id > _queryInfos.Length)
        {
            return;
        }

        // Check it's not already processed, if it is free up the index.
        // If it's processed but the result is that it exists, we should attempt to set it in case it's mismatched an ID
        if (result != DnsResult.EXIST && _completedDomains.Contains(_queryInfos[id].Hostname))
        {
            _queryInfos[id].State = QueryState.NotStarted;
            return;
        }

        lock (_queryLocks[id])
        {
            switch (result)
            {
                case DnsResult.EXIST:
                    // Don't accept the result if they don't match
                    var resSplit = resDomain.Split('\0')[0];
                    if (!_queryInfos[id].Hostname.StartsWith(resSplit) || validSubdomains.Contains(_queryInfos[id].Hostname))
                    {
                        return;
                    }
                    Interlocked.Increment(ref ExistCount);
                    Interlocked.Increment(ref processedCount);
                    validSubdomains.Add(_queryInfos[id].Hostname);
                    _completedDomains.Add(_queryInfos[id].Hostname);
                    _queryInfos[id].State = QueryState.NotStarted;
                    break;
                case DnsResult.SERVFAIL:
                    Interlocked.Increment(ref ServFailCount);
                    Interlocked.Increment(ref processedCount);
                    _completedDomains.Add(_queryInfos[id].Hostname);
                    _queryInfos[id].State = QueryState.NotStarted;
                    break;
                case DnsResult.REFUSED:
                    Interlocked.Increment(ref RefusedCount);
                    //Interlocked.Increment(ref processedCount);
                    //_completedDomains.Add(_queryInfos[id].Hostname);
                    //_queryInfos[id].State = QueryState.NotStarted;
                    break;
                case DnsResult.ERROR:
                    Interlocked.Increment(ref ErrorCount);
                    break;
                case DnsResult.TIME_OUT:
                    Interlocked.Increment(ref TimeoutCount);
                    break;
                case DnsResult.NOT_EXIST:
                    Interlocked.Increment(ref NotExistCount);
                    Interlocked.Increment(ref processedCount);
                    _completedDomains.Add(_queryInfos[id].Hostname);
                    _queryInfos[id].State = QueryState.NotStarted;
                    break;
                case DnsResult.NOT_IMP:
                    NotImpCount++;
                    break;
                default: break; // Ignore it
            }

            Interlocked.Increment(ref AllCount);
        }
    }

    private async Task PrintSimpleStats(CancellationToken cancelToken)
    {
        while (!cancelToken.IsCancellationRequested && !IsFinished())
        {
            await Task.Delay(1000, cancelToken);
            var printOut = $"\r{processedCount}/{_subdomains.Length} ({(double)processedCount / _subdomains.Length * 100:N2}% Complete)";
            Console.Write(printOut + "  ");
        }
    }

    private async Task PrintAdvancedStats(CancellationToken cancelToken)
    {
        while (!cancelToken.IsCancellationRequested && !IsFinished())
        {
            await Task.Delay(1000, cancelToken);
            var printOut = $"\rS_Pending {GetSendQueueSize()} | R_Pending {GetRetrieveQueueSize()} | S {sentCount} | R {AllCount} | Err: {ErrorCount} | Refuse {RefusedCount} | ServFail {ServFailCount} | Timeout {TimeoutCount} | Not Imp {NotImpCount} | Not Exist {NotExistCount} | Exist {ExistCount} | Total {processedCount}/{_subdomains?.Length ?? 0}";
            Console.Write(printOut + "  ");
        }
    }
}

public struct QueryInfo
{
    public string Hostname;
    public DateTime StartTime;
    public QueryState State;
}

public enum QueryState
{
    NotStarted,
    Running,
    TimedOut,
    Queued
}