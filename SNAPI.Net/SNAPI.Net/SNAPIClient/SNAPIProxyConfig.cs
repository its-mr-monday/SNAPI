using System;
using System.Text;

namespace SNAPI.Net.SNAPIClient
{
	public class SNAPIProxyConfig
	{
		private string host;
		private int port;
		private string? auth = null;

		public SNAPIProxyConfig(string host, int port)
		{
			this.host = host;
			this.port = port;
		}

		public SNAPIProxyConfig(string host, int port, string token)
        {
			this.host = host;
			this.port = port;
			this.auth = "{\"token\": \"" + token + "\"}";
        }

		public SNAPIProxyConfig(string host, int port, string username, string password)
        {
			this.host = host;
			this.port = port;
			this.auth = "{\"username\": \"" + username +
						"\", \"password\": \"" + password + "\"}";
        }

		public string GetHost() { return this.host; }

		public int GetPort() { return this.port; }

		public string? GetAuth() { return this.auth; }
	}
}

