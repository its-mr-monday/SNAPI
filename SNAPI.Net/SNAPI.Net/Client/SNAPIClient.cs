using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Security.Cryptography;

namespace SNAPI.Net.Client;

public class SNAPIClient
{
    private string host;
    private int port;
    private bool sslVerify;
    private string? proxy_host = null;
    private int? proxy_port = null;
    private string? proxy_auth = null;
    private SNAPIProxyConfig? proxy_config;

    public SNAPIClient(string host, int port, bool sslVerify = true, SNAPIProxyConfig? proxy_config = null)
    {
        this.proxy_config = proxy_config;
        this.host = host;
        this.port = port;
        this.sslVerify = sslVerify;
        if (this.proxy_config != null)
        {
            this.SetProxy(this.proxy_config);
        }
    }

    public void SetProxy(SNAPIProxyConfig proxy_config)
    {
        this.proxy_config = proxy_config;
        this.proxy_host = proxy_config.GetHost();
        this.proxy_port = proxy_config.GetPort();
        this.proxy_auth = proxy_config.GetAuth();
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

    public SNAPIFileResponse? Download(string route, string filename, string auth="", string srcDir="") {
        string meta = EncodeMetaHeader(route, "DOWNLOAD", auth);
        string json = "{\"filename\":\"" + filename + "\"}";
        byte[] packet = EncodePacket(json, meta);
        SNAPIFileResponse? response =  this.SendDownloadPacket(packet);
        if (srcDir != "" && response != null)
        {
            bool wroteFile = WriteFile(response, Path.Combine(srcDir, filename));
            if (wroteFile != true) Console.WriteLine("Failed to write to file: " + Path.Combine(srcDir, filename));
        }
        return response;
    }

    public SNAPIResponse? Upload(string route, string filename, byte[] filebytes, string auth = "")
    {
        if (filename.Length < 1)
        {
            throw new IOException("Error invalid filename provided to SNAPIClient.Upload()!");
        }
        if (filebytes.Length < 1)
        {
            throw new IOException("Error invalid filebytes provided to SNAPIClient.Upload()!");
        }

        string meta = EncodeMetaHeader(route, "UPLOAD", auth);
        string filedata = Convert.ToBase64String(filebytes);

        SNAPIFilePayload payload = new SNAPIFilePayload {
            Filename = filename,
            Data = filedata,
            Sha256 = ComputeSha256Hash(filebytes),
            Filesize = filedata.Length
        };

        string json = JsonSerializer.Serialize(payload);
        byte[] packet = EncodePacket(json, meta);
        return this.SendPacket(packet);
    }

    public void RemoveProxy()
    {
        this.proxy_config = null;
        this.proxy_auth = null;
        this.proxy_host = null;
        this.proxy_port = null;
    }

    private static byte[] EncodePacket(string payload_json, string meta_inf_json)
    {
        string packet = $"<snapi_req><meta>{meta_inf_json}</meta><payload>{payload_json}</payload></snapi_req>";
        return Encoding.UTF8.GetBytes(packet);
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
        clientStream.AuthenticateAsClient(this.host);
        return clientStream;
    }

    private SNAPIResponse? SendPacket(byte[] packet)
    {
        try {
            using (TcpClient client = setupTcpClient())
            {
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
                string response_str = Encoding.UTF8.GetString(response_bytes);
                Console.WriteLine(response_str);
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
                string response_str = Encoding.UTF8.GetString(response_bytes);
                Console.WriteLine(response_str);
                string json_payload = FindBetween(response_str, "<payload>", "</payload>");
                
                SNAPIFileResponse? fileResponse = JsonSerializer.Deserialize<SNAPIFileResponse>(json_payload);
                return fileResponse;
            }
        } catch (Exception e) {
            Console.WriteLine(e);
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

    public static bool WriteFile(SNAPIFileResponse fileResponse, string srcPath)
    {
        if (fileResponse.Filename == "") return false;
        if (fileResponse.Data == "") return false;
        byte[] fileBytes = Convert.FromBase64String(fileResponse.Data);

        string hash = ComputeSha256Hash(fileBytes);
        if (hash != fileResponse.Sha256) return false;

        if (File.Exists(srcPath) || Directory.Exists(srcPath)) return false;

        File.WriteAllBytes(srcPath, fileBytes);
        return true;
    }

    public static byte[]? GetFileBytes(SNAPIFileResponse fileResponse)
    {
        if (fileResponse.Filename == "") return null;
        if (fileResponse.Data == "") return null;
        byte[] fileBytes = Convert.FromBase64String(fileResponse.Data);
        string hash = ComputeSha256Hash(fileBytes);

        if (hash != fileResponse.Sha256) return null;

        return fileBytes;
    }

    private static string ComputeSha256Hash(byte[] data)
    {
        using (SHA256 sha = SHA256.Create())
        {
            byte[] hashed = sha.ComputeHash(data);

            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < hashed.Length; i++)
            {
                sb.Append(hashed[i].ToString("x2"));
            }
            return sb.ToString();
        }
    }
}