using System;
using SNAPI.Net.Server;

namespace SNAPI.Net.SmapleServer
{
	public class Server
	{
		public Server()
		{
			string certificate = "";
			SNAPIServer api = new SNAPIServer(certificate);
			api.AddRoute("/", Routes.Index);
			api.Serve();
		}
	}
}

