using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.IO;

namespace SNAPI.Net.SNAPIClient;

public class SNAPIClient
{
    private string host;
    private int port;
    private bool sslVerify;
    private string? proxy_host;
    private int? proxy_port;
    private string? proxy_auth;

    public SNAPIClient(string host, int port, bool sslVerify = true,
        string? proxy_host = null, int? proxy_port = null, string? proxy_auth = null)
    {
        this.host = host;
        this.port = port;
        this.sslVerify = sslVerify;
        this.proxy_host = proxy_host;
        this.proxy_port = proxy_port;
        this.proxy_auth = proxy_auth;
    }

    public void SetProxy(string proxy_host, int proxy_port)
    {
        this.proxy_host = proxy_host;
        this.proxy_port = proxy_port;
    }

    public void SetProxyAuthToken(string token)
    {
        this.proxy_auth = "{\"token\":\""+token+"\"}";
    }

    public void SetProxyAuthCreds(string username, string password)
    {
        this.proxy_auth = "{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}";
    }

    private string EncodeMetaHeader(string route, string request_type, string auth) {
        StringBuilder sb = new StringBuilder();
        sb.Append("{");
        sb.Append($"\"route\":\"{route}\",\"request_type\":\"{request_type}\"");
        if (auth != "")
        {
            sb.Append($",\"auth\":\"{auth}\"");
        }
        if (this.proxy_host != null && this.proxy_port != null)
        {
            sb.Append($",\"server\":\"{this.host}\",\"server_port\":{this.port.ToString()}");
            if (this.proxy_auth != null)
            {
                sb.Append($",\"proxy_auth\":{this.proxy_auth}");
            }
        }
        sb.Append("}");
        return sb.ToString();
    }
    public SNAPIResponse? Post(string route, string json_payload, string auth="")
    {
        string meta = EncodeMetaHeader(route, "POST", auth);
        byte[] packet = EncodePacket(json_payload, meta);
        return this.SendPacket(packet);
    }

    public SNAPIResponse? Get(string route, string json_payload="{}", string auth="")
    {
        string meta = EncodeMetaHeader(route, "GET", auth);
        byte[] packet = EncodePacket(json_payload, meta);
        return this.SendPacket(packet);
    }

    public SNAPIFileResponse? Download(string route, string filename, string auth="") {
        string meta = EncodeMetaHeader(route, "DOWNLOAD", auth);
        string json = "{\"filename\":\"" + filename + "\"}";
        byte[] packet = EncodePacket(json, meta);
        return this.SendDownloadPacket(packet);
    }
    public void RemoveProxy()
    {
        this.proxy_auth = null;
        this.proxy_host = null;
        this.proxy_port = null;
    }

    private static byte[] EncodePacket(string payload_json, string meta_inf_json)
    {
        string packet = $"<snapi_req><meta>{meta_inf_json}</meta><payload>{payload_json}</payload></snapi_req>";
        return Encoding.ASCII.GetBytes(packet);
    }

    private static SNAPIResponse DecodePacket(string packet)
    {
        string payload = FindBetween(packet, "<payload>", "</payload>");
        string meta = FindBetween(packet, "<meta>", "</meta>");
        return new SNAPIResponse(meta, payload);
    }

    private static string FindBetween(string src, string first, string last)
    {
        int pFrom = src.IndexOf(first) + first.Length;
        int pTo = src.IndexOf(last, pFrom);
        return src.Substring(pFrom, pTo - pFrom);
    }

    private TcpClient setupTcpClient() {
        string hostaddr = this.host;
        int hostport = this.port;
        if (this.proxy_host != null && this.proxy_port != null) {
            hostaddr = this.proxy_host;
            hostport = this.proxy_port.Value;
        }
        TcpClient tcpClient = new TcpClient(hostaddr, hostport);
        return tcpClient;
    }

    private SslStream setupSslStream(TcpClient client) {
        SslStream clientStream;
        if (this.sslVerify == false) {
            clientStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);
        } else {
            clientStream = new SslStream(client.GetStream(), false, null, null);
        }
        return clientStream;
    }
    private SNAPIResponse? SendPacket(byte[] packet)
    {
        try {
            using (TcpClient client = setupTcpClient()) {
                SslStream clientStream = setupSslStream(client);
                clientStream.Write(packet);
                clientStream.Flush();
                List<byte> response = new List<byte>();
                while (true) {
                    byte[] buffer = new byte[1024];
                    int bytesRead = clientStream.Read(buffer, 0, buffer.Length);
                    if (bytesRead == 0) {
                        break;
                    }
                    response.AddRange(buffer);
                }
                clientStream.Close();
                client.Close();
                byte[] response_bytes = response.ToArray();
                string response_str = Encoding.ASCII.GetString(response_bytes);
                return DecodePacket(response_str);
            }
        } catch (Exception e) {
            Console.WriteLine(e.ToString());
            return null;
        }
    }

    private SNAPIFileResponse? SendDownloadPacket(byte[] packet) {
        try {
            using (TcpClient client = setupTcpClient()) {
                SslStream clientStream = setupSslStream(client);
                clientStream.Write(packet);
                clientStream.Flush();
                List<byte> response = new List<byte>();
                while (true) {
                    byte[] buffer = new byte[1024];
                    int bytesRead = clientStream.Read(buffer, 0, buffer.Length);
                    if (bytesRead == 0) {
                        break;
                    }
                    response.AddRange(buffer);
                }
                clientStream.Close();
                client.Close();
                byte[] response_bytes = response.ToArray();
                string response_str = Encoding.ASCII.GetString(response_bytes);
                SNAPIFileResponse? fileResponse = JsonSerializer.Deserialize<SNAPIFileResponse>(response_str);
                return fileResponse;
            }
        } catch (Exception e) {
            Console.WriteLine(e.ToString());
            return null;
        }
    }
    private static bool ValidateServerCertificate(object sender,X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors){
        if (sslPolicyErrors == SslPolicyErrors.None){
            return true;
        }

            //Console.WriteLine("Certificate error: {0}", sslPolicyErrors);

            // Do not allow this client to communicate with unauthenticated servers.
        return true;
    }

}

