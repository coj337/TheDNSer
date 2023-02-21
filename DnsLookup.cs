using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace DNS_Bruteforce;

public class DnsLookup
{
    private const int DNS_PORT = 53;
    private const int PACKET_SIZE = 256;

    private IPAddress[] _dnsServers;
    private int _lastUsedDnsServerIndex;
    //private QueryInfo[] _queryInfos;
    private ConcurrentDictionary<ushort, (string, IPAddress, DateTime)> _queryIdMap;

    private static readonly IPEndPoint _blankEndpoint = new(IPAddress.Any, 0);

    public DnsLookup(IPAddress[] dnsServers)
    {
        _dnsServers = dnsServers;
        _lastUsedDnsServerIndex = 0;
       // _queryInfos = new QueryInfo[ushort.MaxValue]; // Set the maximum number of concurrent queries to the max ushort (to match IDs)
        _queryIdMap = new ConcurrentDictionary<ushort, (string, IPAddress, DateTime)>();
    }

    // Cool opts - https://enclave.io/high-performance-udp-sockets-net6
    public async Task SendAsync(string hostname, Socket udpSocket, CancellationToken cancelToken)
    {
        // Domain parts are split in the domain bytes so we need to add an extra spot for each part
        var domainParts = hostname.Count(c => c == '.')+1;

        // Taking advantage of pre-pinned memory here using the .NET 5 POH (pinned object heap).
        byte[] buffer = GC.AllocateArray<byte>(12 + hostname.Length + 4 + domainParts, pinned: true);
        Memory<byte> bufferMem = buffer.AsMemory();

        // Put request data in the buffer
        BuildQueryMessage(hostname, bufferMem.Span);

        // Store query info
        ushort queryId;
        do
        {
            Random.Shared.NextBytes(bufferMem.Span[..2]);
            queryId = BinaryPrimitives.ReadUInt16BigEndian(bufferMem.Span[..2]);
        }
        while (!_queryIdMap.TryAdd(queryId, (hostname, _dnsServers[_lastUsedDnsServerIndex], DateTime.UtcNow)));

        // Send it™️
        await udpSocket.SendToAsync(bufferMem, SocketFlags.None, new IPEndPoint(_dnsServers[_lastUsedDnsServerIndex], DNS_PORT), cancelToken);

        // Increment the index to the next DNS server
        _lastUsedDnsServerIndex = (_lastUsedDnsServerIndex + 1) % _dnsServers.Length;
    }

    public bool IsQueueEmpty()
    {
        return !_queryIdMap.Any();
    }

    public async Task ReceiveAsync(Socket udpSocket, CancellationToken cancelToken, Func<ushort, DnsResult, string, string, Task> callback)
    {
        // Taking advantage of pre-pinned memory here using the .NET5 POH (pinned object heap).
        byte[] buffer = GC.AllocateArray<byte>(PACKET_SIZE, pinned: true);
        Memory<byte> bufferMem = buffer.AsMemory();
        if(!udpSocket.IsBound)
        {
            udpSocket.Bind(_blankEndpoint);
        }

        while (!cancelToken.IsCancellationRequested)
        {
            var result = await udpSocket.ReceiveFromAsync(bufferMem, SocketFlags.None, _blankEndpoint, cancelToken);
            await ParseResponseMessage(bufferMem[..result.ReceivedBytes], callback);
        }
    }

    public async Task ResendStaleQueries(CancellationToken cancelToken, Func<ushort, DnsResult, string, string, Task> callback)
    {
        while (!cancelToken.IsCancellationRequested)
        {
            await Task.Delay(1000, cancelToken); // Check every second
            foreach (var query in _queryIdMap.Where(q => q.Value.Item3 < DateTime.UtcNow.AddSeconds(-5)))
            {
                // Remove the old query from the dictionary
                if (_queryIdMap.TryRemove(query.Key, out (string, IPAddress, DateTime) _))
                {
                    await callback(query.Key, DnsResult.TIME_OUT, query.Value.Item2.ToString(), query.Value.Item1);
                }
                else
                {

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
        BinaryPrimitives.WriteUInt16BigEndian(buffer[10..], 0x0000); //  ARCOUNT = 0

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

    private async Task ParseResponseMessage(ReadOnlyMemory<byte> responseMessage, Func<ushort, DnsResult, string, string, Task> callback)
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

        // Get domain and DNS server for this query ID and remove it from the dictionary
        if (_queryIdMap.TryRemove(id, out var queryInfo))
        {
            await callback(id, result, queryInfo.Item2.ToString(), queryInfo.Item1);
        }
        else
        {

        }
    }
}

struct QueryInfo
{
    public string Hostname;
    public IPAddress DnsServer;
    public DateTime StartTime;
    public DnsResult Result;
}