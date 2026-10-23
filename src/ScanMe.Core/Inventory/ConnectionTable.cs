using System.Net;
using System.Runtime.InteropServices;
using ScanMe.Core.Native;

namespace ScanMe.Core.Inventory;

public enum Protocol { Tcp, Udp }

public sealed record Connection(
    Protocol Protocol,
    IPAddress LocalAddress,
    int LocalPort,
    IPAddress? RemoteAddress,
    int RemotePort,
    string State,
    int Pid)
{
    public bool IsListening => Protocol == Protocol.Udp || State == "LISTEN";
    public bool IsEstablished => State == "ESTABLISHED";
    public bool IsExternal => RemoteAddress != null && NetUtil.IsPublic(RemoteAddress);
}

/// <summary>TCP/UDP-Verbindungstabellen inklusive besitzendem Prozess (wie netstat -ano).</summary>
public static class ConnectionTable
{
    private static readonly string[] TcpStates =
        ["?", "CLOSED", "LISTEN", "SYN_SENT", "SYN_RCVD", "ESTABLISHED", "FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT", "CLOSING", "LAST_ACK", "TIME_WAIT", "DELETE_TCB"];

    public static List<Connection> Capture()
    {
        var list = new List<Connection>();
        list.AddRange(ReadTcp4());
        list.AddRange(ReadTcp6());
        list.AddRange(ReadUdp4());
        list.AddRange(ReadUdp6());
        return list;
    }

    private static int Port(uint raw) => (int)(((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF));

    private static IntPtr Fetch(Func<IntPtr, int, (uint Result, int Size)> call)
    {
        var (_, size) = call(IntPtr.Zero, 0);
        for (int attempt = 0; attempt < 5; attempt++)
        {
            size += 4096;
            IntPtr buf = Marshal.AllocHGlobal(size);
            var (result, needed) = call(buf, size);
            if (result == 0) return buf;
            Marshal.FreeHGlobal(buf);
            size = needed;
        }
        return IntPtr.Zero;
    }

    private static IEnumerable<Connection> ReadTcp4()
    {
        IntPtr buf = Fetch((b, s) => { int sz = s; uint r = NativeMethods.GetExtendedTcpTable(b, ref sz, false, NativeMethods.AF_INET, NativeMethods.TCP_TABLE_OWNER_PID_ALL, 0); return (r, sz); });
        if (buf == IntPtr.Zero) yield break;
        try
        {
            int count = Marshal.ReadInt32(buf);
            int rowSize = Marshal.SizeOf<NativeMethods.MIB_TCPROW_OWNER_PID>();
            for (int i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<NativeMethods.MIB_TCPROW_OWNER_PID>(buf + 4 + i * rowSize);
                yield return new Connection(Protocol.Tcp, new IPAddress(row.localAddr), Port(row.localPort),
                    new IPAddress(row.remoteAddr), Port(row.remotePort), TcpStates[Math.Min(row.state, (uint)TcpStates.Length - 1)], row.owningPid);
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    private static unsafe List<Connection> ReadTcp6()
    {
        var result = new List<Connection>();
        IntPtr buf = Fetch((b, s) => { int sz = s; uint r = NativeMethods.GetExtendedTcpTable(b, ref sz, false, NativeMethods.AF_INET6, NativeMethods.TCP_TABLE_OWNER_PID_ALL, 0); return (r, sz); });
        if (buf == IntPtr.Zero) return result;
        try
        {
            int count = Marshal.ReadInt32(buf);
            var rows = (NativeMethods.MIB_TCP6ROW_OWNER_PID*)(buf + 4);
            for (int i = 0; i < count; i++)
            {
                var row = rows[i];
                var local = new IPAddress(new ReadOnlySpan<byte>(row.localAddr, 16), row.localScopeId);
                var remote = new IPAddress(new ReadOnlySpan<byte>(row.remoteAddr, 16), row.remoteScopeId);
                result.Add(new Connection(Protocol.Tcp, local, Port(row.localPort), remote, Port(row.remotePort),
                    TcpStates[Math.Min(row.state, (uint)TcpStates.Length - 1)], row.owningPid));
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
        return result;
    }

    private static IEnumerable<Connection> ReadUdp4()
    {
        IntPtr buf = Fetch((b, s) => { int sz = s; uint r = NativeMethods.GetExtendedUdpTable(b, ref sz, false, NativeMethods.AF_INET, NativeMethods.UDP_TABLE_OWNER_PID, 0); return (r, sz); });
        if (buf == IntPtr.Zero) yield break;
        try
        {
            int count = Marshal.ReadInt32(buf);
            int rowSize = Marshal.SizeOf<NativeMethods.MIB_UDPROW_OWNER_PID>();
            for (int i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<NativeMethods.MIB_UDPROW_OWNER_PID>(buf + 4 + i * rowSize);
                yield return new Connection(Protocol.Udp, new IPAddress(row.localAddr), Port(row.localPort), null, 0, "", row.owningPid);
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    private static unsafe List<Connection> ReadUdp6()
    {
        var result = new List<Connection>();
        IntPtr buf = Fetch((b, s) => { int sz = s; uint r = NativeMethods.GetExtendedUdpTable(b, ref sz, false, NativeMethods.AF_INET6, NativeMethods.UDP_TABLE_OWNER_PID, 0); return (r, sz); });
        if (buf == IntPtr.Zero) return result;
        try
        {
            int count = Marshal.ReadInt32(buf);
            var rows = (NativeMethods.MIB_UDP6ROW_OWNER_PID*)(buf + 4);
            for (int i = 0; i < count; i++)
            {
                var row = rows[i];
                var local = new IPAddress(new ReadOnlySpan<byte>(row.localAddr, 16), row.localScopeId);
                result.Add(new Connection(Protocol.Udp, local, Port(row.localPort), null, 0, "", row.owningPid));
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
        return result;
    }
}

public static class NetUtil
{
    public static bool IsPublic(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any) || ip.Equals(IPAddress.IPv6None)) return false;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            return !(ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6Multicast || ip.IsIPv6UniqueLocal);
        byte[] b = ip.GetAddressBytes();
        return !(b[0] == 10
                 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                 || (b[0] == 192 && b[1] == 168)
                 || (b[0] == 169 && b[1] == 254)
                 || (b[0] == 100 && b[1] >= 64 && b[1] <= 127) // CGNAT
                 || b[0] == 0 || b[0] >= 224);
    }
}
