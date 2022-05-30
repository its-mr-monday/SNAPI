using System;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using SNAPI.Net.SNAPIException;

namespace SNAPI.Net.Server
{
	public sealed class SNAPIServer
	{
		private int port = 5001;		//Default port for SNAPI servers 
		private int max_threads;
		private string certFile;
		private X509Certificate? serverCert = null;
		private TcpListener? tcpListener = null;
		private bool running = false;
		private List<Thread> active_threads;
		private Thread? cleanupThread = null;
		private Dictionary<string, Func<SNAPIRequest, SNAPIResponse>> route_map;

		public SNAPIServer(string certificateFile, int max_threads=50)
		{
			this.certFile = certificateFile;
			this.serverCert = X509Certificate.CreateFromCertFile(certificateFile);
			this.max_threads = max_threads;
			this.active_threads = new List<Thread>();
			this.route_map = new Dictionary<string, Func<SNAPIRequest, SNAPIResponse>>();
		}

		public void Serve(string host="0.0.0.0", int port = 5001)
        {
			Console.WriteLine($"Starting SNAPI.Net (Secure Network Application Interface) Server on port: {port}");
			this.running = true;
			try
			{
				this.port = port;
				this.cleanupThread = new Thread(() => this.cleanupThreads());
				this.cleanupThread.Start();
				if (this.tcpListener != null)
				{
					throw new SNAPIServerException("Error tcpListener object already created!");
				}


				this.tcpListener = SetupListener(host, this.port);
				this.tcpListener.Start();
				while (true)
				{
					TcpClient newClient = this.tcpListener.AcceptTcpClient();
					ProcessClient(newClient);
				}
			} catch (Exception e)
            {
				Console.WriteLine(e);
				Console.WriteLine("\nSNAPI Server shutting down!");
				this.suspendThreads();
            }

        }

		private void ProcessClient(TcpClient client)
        {
			SslStream sslStream = new SslStream(client.GetStream(), false);
			try
            {
				sslStream.AuthenticateAsServer(this.serverCert, clientCertificateRequired: false, checkCertificateRevocation: true);

				if (this.active_threads.Count >= this.max_threads)
                {
					string payload = "{ \"message\" : \"Server is busy\"}";
					byte[] packet = EncodePacket(payload, 503);
					sslStream.Write(packet);
					sslStream.Close();
					client.Close();
					return;
                } else
                {
					Thread clientThread = new Thread(() => HandleClientThread(client, sslStream));
					clientThread.Start();
					this.active_threads.Add(clientThread);
					return;
                }

            } catch (AuthenticationException e)
            {
				Console.WriteLine(e);
				sslStream.Close();
				client.Close();
            }
        }

		private void HandleClientThread(TcpClient client, SslStream sslStream)
        {
			//In this thread we handle client requests
			MemoryStream ms = new MemoryStream();
			while (true)
            {
				try
                {
					byte[] buffer = new byte[1024];
					int bytesRead = sslStream.Read(buffer);
					if (bytesRead > 1)
                    {
						break;
                    }
					ms.Write(buffer, 0, bytesRead);

                } catch (Exception e)
                {
					Console.WriteLine(e);
					break;
                }
            }
			byte[] request_packt = ms.ToArray();
			SNAPIRequest request = DecodePacket(Encoding.UTF8.GetString(request_packt));
			SNAPIResponse response = new SNAPIResponse(400, encodedJsonPayload: "{\"message\": \"Bad Request\"}");
			if (!(request.GetRequestMetaDataObject() == null)
				|| !(request.GetRequestMetaDataObject().Route == "") || ! (request.GetRequestMetaDataObject().Request_type == ""))
            {
				string route = request.GetRequestMetaDataObject().Route;
				if (this.route_map.ContainsKey(route))
				{
					string req_type = request.GetRequestMetaDataObject().Request_type;
					response = this.route_map[route](request);
					this.LogRequest(route, response.GetReturnCode(), client.Client.RemoteEndPoint.ToString(), DateTime.Now.ToString(), req_type);
				} else
                {
					response = new SNAPIResponse(404, encodedJsonPayload: "{\"message\": \"404 Route Not Found\" }");
                }
			}
			else
            {
				this.LogError(DateTime.Now.ToString(), "Error Invalid Request!");
            }
			
			byte[] packet = EncodePacket(response.GetPayload(), response.GetReturnCode());
			sslStream.Write(packet);
			sslStream.Close();
			client.Close();
			return;
        }

		private static TcpListener SetupListener(string host, int port)
        {
			IPAddress? hostAddr = null;
			IPAddress.TryParse(host, out hostAddr);

			if (hostAddr != null)
            {
				return new TcpListener(hostAddr, port);
            }
			throw new SNAPIServerException("Error host address passed in was not a valid IPAddress!");
        }

		public void AddRoute(string route, Func<SNAPIRequest, SNAPIResponse> handler)
        {
			if (route_map.ContainsKey(route))
            {
				throw new SNAPIServerException($"Error route {route} already exists");
            }
			this.route_map.Add(route, handler);
        }

		public void AddDownload(string route, string srcDir, Func<string, bool>? authMethod = null)
        {
			if (route_map.ContainsKey(route))
            {
				throw new SNAPIServerException($"Error route {route} already exists");
			}
			this.route_map.Add(route, req =>
			{
				return DownloadHandler(srcDir, req, authMethod: authMethod);
			});
        }

		private SNAPIResponse DownloadHandler(string srcDir, SNAPIRequest request, Func<string, bool>? authMethod = null)
        {
			SNAPIRequestMetaData? metaData = request.GetRequestMetaDataObject();
			if (metaData == null || metaData.Request_type != "DWONLOAD")
            {
				//
				return new SNAPIResponse(400, encodedJsonPayload: "{ \"message\": \"Bad Request\" }");
            }

			string json_payload = request.GetJsonPayload();
			SNAPIDownloadRequest? download_request = JsonSerializer.Deserialize<SNAPIDownloadRequest>(json_payload);
			if (download_request == null)
            {
				return new SNAPIResponse(400, encodedJsonPayload: "{ \"message\": \"Bad Request\" }");
			}

			if (authMethod != null)
            {
				if (metaData.Auth == "" || !authMethod(metaData.Auth))
                {
					return new SNAPIResponse(401, encodedJsonPayload: "{\"message\":\"Unauthorized\"}");
                }
            }

			string filename = download_request.Filename;

			if (filename == "")
            {
				return new SNAPIResponse(400, encodedJsonPayload: "{ \"message\": \"Bad Request\" }");
			}

			string filePath = Path.Combine(srcDir, filename);

			//Prevent file system traversal
			string? srcpathdir = Path.GetDirectoryName(filePath);
			if (srcpathdir == null || srcpathdir != srcDir)
            {
				return new SNAPIResponse(400, encodedJsonPayload: "{ \"message\": \"Bad Request\" }");
			}

			if (!File.Exists(filePath))
            {
				return new SNAPIResponse(404, encodedJsonPayload: "{\"message\":\"File Not Found\"}");
            }

			byte[] filebytes = File.ReadAllBytes(filePath);
			string filehash = ComputeSha256Hash(filebytes);
			string b64bytes = Convert.ToBase64String(filebytes);
			int size = b64bytes.Length;

			SNAPIDownloadResponse downloadResponse = new SNAPIDownloadResponse
			{
				Sha256 = filehash,
				Filesize = size,
				Data = b64bytes,
				Filename = filename
			};

			string json_payload_response = JsonSerializer.Serialize<SNAPIDownloadResponse>(downloadResponse);
			return new SNAPIResponse(200, encodedJsonPayload: json_payload_response);
		}

		private static byte[] EncodePacket(string json_payload, int meta_inf)
        {
			string json_meta = "{\"response_code\": " + meta_inf.ToString() + "}";
			string packet = $"<snapi_res><meta>{json_meta}</meta><payload>{json_payload}</payload></snapi_res>";

			return Encoding.ASCII.GetBytes(packet);
        }

		private static string FindBetween(string src, string first, string last)
		{
			int pFrom = src.IndexOf(first) + first.Length;
			int pTo = src.IndexOf(last, pFrom);
			return src.Substring(pFrom, pTo - pFrom);
		}

		public SNAPIRequest DecodePacket(string packet)
        {
			string meta_str = FindBetween(packet, "<meta>", "</meta>");
			string payload_str = FindBetween(packet, "<payload>", "</paylaod>");
			return new SNAPIRequest(meta_str, payload_str);
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

		private void LogRequest(string route, int response_code, string ipaddr, string time, string req_type)
        {
			Console.WriteLine($"[{time}] {ipaddr} {response_code} {req_type} {route}");
        }

		private void LogError(string time, string errorMessage)
        {
			Console.WriteLine($"[{time}] Error: {errorMessage}");
        }

		private void cleanupThreads()
        {
			while (this.running)
            {
				foreach (Thread thread in this.active_threads) {
					if (thread.IsAlive) continue;
					this.active_threads.Remove(thread);
                }
				Thread.Sleep(1000);		//Sleep every second
            }
        }

		private void suspendThreads()
        {
			this.running = false;
			foreach (Thread thread in this.active_threads)
            {
				if (thread.IsAlive) thread.Join();
            }
			this.cleanupThread.Join();
        }
	}
}

