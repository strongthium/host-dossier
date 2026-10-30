using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Strongthium.HostDossier.Tests;

/// <summary>A DNS server on the loopback address that answers from a table, so that whatever reads the DNS can be
/// tested on exactly the records it should meet. A name with no records at all doesn't exist; a name with records of
/// other types answers with nothing.</summary>
internal sealed class FakeDns : IDisposable
{
    private const ushort A = 1, Ptr = 12, Mx = 15, Txt = 16, Aaaa = 28;

    private readonly UdpClient socket = new(new IPEndPoint(IPAddress.Loopback, 0));
    private readonly Dictionary<(string Name, ushort Type), List<byte[]>> table = [];
    private readonly CancellationTokenSource stop = new();
    private readonly Task loop;

    public string Address => $"127.0.0.1:{((IPEndPoint)socket.Client.LocalEndPoint!).Port}";

    public FakeDns() => loop = Task.Run(ServeAsync);

    public FakeDns Text(string name, string text)
    {
        var bytes = Encoding.ASCII.GetBytes(text);
        var data = new List<byte>();
        foreach (var chunk in bytes.Chunk(255))
        {
            data.Add((byte)chunk.Length);
            data.AddRange(chunk);
        }
        return Add(name, Txt, data.ToArray());
    }

    public FakeDns Address4(string name, string ip) => Add(name, A, IPAddress.Parse(ip).GetAddressBytes());

    public FakeDns Address6(string name, string ip) => Add(name, Aaaa, IPAddress.Parse(ip).GetAddressBytes());

    public FakeDns Pointer(string name, string host) => Add(name, Ptr, Labels(host));

    public FakeDns Mail(string name, int preference, string host)
    {
        var data = new List<byte> { (byte)(preference >> 8), (byte)preference };
        data.AddRange(Labels(host));
        return Add(name, Mx, data.ToArray());
    }

    private FakeDns Add(string name, ushort type, byte[] data)
    {
        var key = (name.ToLowerInvariant(), type);
        if (!table.TryGetValue(key, out var list)) table[key] = list = [];
        list.Add(data);
        return this;
    }

    private static byte[] Labels(string name)
    {
        var bytes = new List<byte>();
        foreach (var label in name.Split('.'))
        {
            bytes.Add((byte)label.Length);
            bytes.AddRange(Encoding.ASCII.GetBytes(label));
        }
        bytes.Add(0);
        return bytes.ToArray();
    }

    private async Task ServeAsync()
    {
        while (!stop.IsCancellationRequested)
        {
            UdpReceiveResult request;
            try
            {
                request = await socket.ReceiveAsync(stop.Token);
            }
            catch (Exception exception) when (exception is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                if (stop.IsCancellationRequested) return;
                continue;
            }
            var answer = Answer(request.Buffer);
            try
            {
                await socket.SendAsync(answer, request.RemoteEndPoint, stop.Token);
            }
            catch (Exception exception) when (exception is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                // The test is over, or the asker has gone.
            }
        }
    }

    private byte[] Answer(byte[] query)
    {
        var position = 12;
        var name = new StringBuilder();
        while (query[position] != 0)
        {
            var length = query[position];
            if (name.Length > 0) name.Append('.');
            name.Append(Encoding.ASCII.GetString(query, position + 1, length));
            position += length + 1;
        }
        position++;
        var type = (ushort)((query[position] << 8) | query[position + 1]);
        var questionEnd = position + 4;

        var asked = name.ToString().ToLowerInvariant();
        var exists = table.Keys.Any(k => k.Name == asked);
        var records = table.GetValueOrDefault((asked, type)) ?? [];

        var reply = new List<byte> { query[0], query[1], 0x81, (byte)(exists ? 0x80 : 0x83), 0, 1, (byte)(records.Count >> 8), (byte)records.Count, 0, 0, 0, 0 };
        reply.AddRange(query[12..questionEnd]);
        foreach (var data in records)
        {
            reply.AddRange([0xC0, 0x0C, (byte)(type >> 8), (byte)type, 0, 1, 0, 0, 0, 60, (byte)(data.Length >> 8), (byte)data.Length]);
            reply.AddRange(data);
        }
        return reply.ToArray();
    }

    public void Dispose()
    {
        stop.Cancel();
        socket.Dispose();
        try { loop.Wait(TimeSpan.FromSeconds(2)); }
        catch (AggregateException) { }
        stop.Dispose();
    }
}
