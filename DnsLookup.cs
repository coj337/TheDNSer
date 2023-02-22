using System.Buffers.Binary;//1.39m
using System.Net;
using System.Net.Sockets;

namespace DNS_Bruteforce;

public class DnsLookup
{
    private const int DNS_PORT = 53;
    private const int PACKET_SIZE = 512;
    private const int RETRY_LIMIT = 50;
    private const int TIMEOUT_MS = 500;

    private readonly int _maxConcurrency;

    private static readonly IPEndPoint _blankEndpoint = new(IPAddress.Any, 0);
    private readonly IPAddress[] _dnsServers;
    private readonly bool[] _dnsServerBlacklist;
    private int blacklistedServers = 0;
    private readonly IPEndPoint _sendEndpoint;
    private int _lastUsedDnsServerIndex;
    private readonly QueryInfo[] _queryInfos;
    private readonly Socket udpSocket;
    private readonly object _sendLock = new(); // Make send thread safe

    // Use a circular buffer instead of Queue<T> to avoid heap allocations
    private KeyValuePair<ushort, Memory<byte>>[] _pendingSends;
    private int _pendingSendsStart = 0;
    private int _pendingSendsEnd = 0;

    // Use a circular buffer instead of Queue<T> to avoid heap allocations
    private Memory<byte>[] _pendingReceives;
    private int _pendingReceivesStart = 0;
    private int _pendingReceivesEnd = 0;

    // Store our results
    public readonly List<string> validSubdomains = new();

    public DnsLookup(IPAddress[] dnsServers, int maxConcurrency)
    {
        _maxConcurrency = maxConcurrency;
        udpSocket = new(SocketType.Dgram, ProtocolType.Udp);
        _dnsServers = dnsServers;
        _dnsServerBlacklist = new bool[dnsServers.Length];
        _pendingReceives = new Memory<byte>[ushort.MaxValue + 1];
        _pendingSends = new KeyValuePair<ushort, Memory<byte>>[ushort.MaxValue + 1];
        _lastUsedDnsServerIndex = 0;
        _queryInfos = new QueryInfo[ushort.MaxValue+1]; // Set the maximum number of concurrent queries to the max ushort (to match IDs) +1 because 0 index
        _sendEndpoint = new IPEndPoint(dnsServers[0], DNS_PORT);
    }

    public void Send(string hostname, ushort? queryId = null)
    {
        Interlocked.Increment(ref submitted);

        // Domain parts are split in the domain bytes so we need to add an extra spot for each part
        var domainParts = hostname.Count(c => c == '.')+1;

        // Taking advantage of pre-pinned memory here using the .NET 5 POH (pinned object heap).
        byte[] buffer = GC.AllocateArray<byte>(12 + hostname.Length + 4 + domainParts, pinned: true);
        Memory<byte> bufferMem = buffer.AsMemory();

        // Put request data in the buffer
        BuildQueryMessage(hostname, bufferMem.Span);

        // Store query info
        lock (_sendLock) // We be thread safe :D
        {
            // Write it if we already have one, retry. Otherwise generate that bad boy
            if (queryId != null)
            {
                BinaryPrimitives.WriteUInt16BigEndian(buffer, queryId.Value);
                _queryInfos[queryId.Value].TryCount++;
            }
            else
            {
                do
                {
                    Random.Shared.NextBytes(bufferMem.Span[..2]);
                    queryId = BinaryPrimitives.ReadUInt16BigEndian(bufferMem.Span[..2]);
                }
                while (_queryInfos[queryId.Value].State != QueryState.NotStarted);
                _queryInfos[queryId.Value].Hostname = hostname;
                _queryInfos[queryId.Value].State = QueryState.Running;
            }

            // Make sure we have DNS servers to use, reset when > half are blacklisted. Otherwise reset blacklist
            if (blacklistedServers > _dnsServers.Length / 2)
            {
                Array.Clear(_dnsServerBlacklist);
                blacklistedServers = 0;
            }

            // Increment the index to the next valid DNS server
            do
            {
                _lastUsedDnsServerIndex = (_lastUsedDnsServerIndex + 1) % _dnsServers.Length;
            }
            while (_dnsServerBlacklist[_lastUsedDnsServerIndex]);

            // Assign the tracking variables
            _queryInfos[queryId.Value].DnsServerIndex = _lastUsedDnsServerIndex;
            _queryInfos[queryId.Value].StartTime = DateTime.UtcNow;

            if(_queryInfos[queryId.Value].TryCount >= RETRY_LIMIT)
            {
                // Nope it
                _queryInfos[queryId.Value].State = QueryState.Failed;
                Interlocked.Increment(ref processedCount);
            }
            else
            {
                _pendingSends[_pendingSendsEnd] = KeyValuePair.Create(queryId.Value, bufferMem);
                _pendingSendsEnd = (_pendingSendsEnd + 1) % _pendingSends.Length;
            }
        }
    }

    public async Task StartSendProcessorAsync(CancellationToken cancelToken)
    {
        while (!cancelToken.IsCancellationRequested)
        {
            KeyValuePair<ushort, Memory<byte>> currentItem;

            // This is effectively `currentItem = _pendingSends.Dequeue()`
            if (_pendingSendsStart != _pendingSendsEnd)
            {
                currentItem = _pendingSends[_pendingSendsStart];
                _pendingSendsStart = (_pendingSendsStart + 1) % _pendingSends.Length;
            }
            else
            {
                currentItem = default;
            }

            // Make sure we have a real item and we're not breaking concurrency rules
            if (currentItem.Value.Length > 0 && sentCount - processedCount < _maxConcurrency)
            {
                if(_queryInfos[currentItem.Key].State != QueryState.Running)
                {
                    continue; // Sneaky record raced and tried to go twice
                }

                // Send it™️
                _sendEndpoint.Address = _dnsServers[_queryInfos[currentItem.Key].DnsServerIndex];
                sentCount++;
                await udpSocket.SendToAsync(currentItem.Value, SocketFlags.None, _sendEndpoint, cancelToken);
            }
            else
            {
                await Task.Delay(1000, cancelToken); // Wait if we're waiting for more packets
            }
        }
    }

    public async Task ProcessReceiveQueueAsync(CancellationToken cancelToken)
    {
        if (!udpSocket.IsBound)
        {
            udpSocket.Bind(_blankEndpoint);
        }

        while (!cancelToken.IsCancellationRequested)
        {
            // Use pre-pinned memory using the .NET5 POH (pinned object heap).
            byte[] buffer = GC.AllocateArray<byte>(PACKET_SIZE, pinned: true);
            Memory<byte> bufferMem = buffer.AsMemory();

            try
            {
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
                    // Buffer full, drop the packet
                }
            }
            catch (SocketException ex)
            {
                if (ex.SocketErrorCode == SocketError.ConnectionReset || ex.SocketErrorCode == SocketError.TimedOut)
                {
                    // Ignore these errors, they're expected in some cases
                }
                else
                {
                    throw;
                }
            }
        }
    }

    public bool IsQueueEmpty()
    {
        return _queryInfos.All(q => q.State == QueryState.Complete || q.State == QueryState.NotStarted || q.State == QueryState.Failed);
    }

    public async Task StartReceivedProcessorAsync(CancellationToken cancelToken)
    {
        while (!cancelToken.IsCancellationRequested)
        {
            if (GetRetreiveQueueSize() > 0)
            {
                // Effectively `var currentItem = Queue<T>.Dequeue()`
                var currentItem = _pendingReceives[_pendingReceivesStart];
                _pendingReceivesStart = (_pendingReceivesStart + 1) % _pendingReceives.Length;

                ParseResponseMessage(currentItem);
            }
            else
            {
                await Task.Delay(1000, cancelToken); // Wait if we're waiting for more packets
            }
        }
    }

    public async Task ResendStaleQueries(CancellationToken cancelToken)
    {
        while (!cancelToken.IsCancellationRequested)
        {
            await Task.Delay(1000, cancelToken); // Check every second
            var now = DateTime.UtcNow;
            for (uint i = 0; i < _queryInfos.Length; i++)
            {
                if (_queryInfos[i].State == QueryState.Running && _queryInfos[i].StartTime < now.AddMilliseconds(TIMEOUT_MS*-1))
                {
                    ProcessStats((ushort)i, DnsResult.TIME_OUT, _queryInfos[i].DnsServerIndex, _queryInfos[i].Hostname ?? "");
                }
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
        if (responseMessage.Length < 12)
        {
            throw new FormatException("Invalid DNS response message");
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
            }
        }

        // Process this boi
        ProcessStats(id, result, _queryInfos[id].DnsServerIndex, _queryInfos[id].Hostname ?? "");
    }

    public int GetSendQueueSize()
    {
        return (_pendingSendsEnd - _pendingSendsStart + _pendingSends.Length) % _pendingSends.Length;
    }

    public int GetRetreiveQueueSize()
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
    private void ProcessStats(ushort id, DnsResult result, int dnsServerIndex, string domain)
    {
        //Chance we hit this twice if we race as a stale query, we only care about once
        if (_queryInfos[id].State == QueryState.Complete || _queryInfos[id].State == QueryState.Failed)
        {
            return;
        }
        
        switch (result)
        {
            case DnsResult.EXIST:
                ExistCount++;
                Interlocked.Increment(ref processedCount);
                validSubdomains.Add(domain);
                _queryInfos[id].State = QueryState.Complete;
                break;
            case DnsResult.SERVFAIL:
                ServFailCount++;
                Interlocked.Increment(ref processedCount);
                _queryInfos[id].State = QueryState.Complete;
                break;
            case DnsResult.REFUSED:
                RefusedCount++;
                Interlocked.Increment(ref processedCount);
                _queryInfos[id].State = QueryState.Complete;
                break;
            case DnsResult.ERROR:
                ErrorCount++;
                Send(domain, id);
                break;
            case DnsResult.TIME_OUT:
                TimeoutCount++;
                // Blacklist server for timing out ):<
                // TODO: Add a timeout so it comes back (massdns does 60 seconds)
                _dnsServerBlacklist[dnsServerIndex] = true;
                blacklistedServers++;
                Send(domain, id);
                break;
            case DnsResult.NOT_EXIST:
                NotExistCount++;
                Interlocked.Increment(ref processedCount);
                _queryInfos[id].State = QueryState.Complete;
                break;
            case DnsResult.NOT_IMP:
                NotImpCount++;
                Send(domain, id);
                break;
            default: throw new Exception("Unexcepted DNS result!");
        }

        AllCount++;
    }
}

struct QueryInfo
{
    public string? Hostname;
    public int DnsServerIndex;
    public DateTime StartTime;
    public int TryCount;
    public QueryState State;
}

enum QueryState
{
    NotStarted,
    Running,
    Complete,
    Failed
}