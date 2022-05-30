using System;
namespace SNAPI.Net.SNAPIException;


public class SNAPIServerException : Exception
{
	public SNAPIServerException(string errorMessage) : base(errorMessage) {
	}

	public SNAPIServerException(string errorMessage, Exception innerException) : base(errorMessage, innerException)
    {}
}

public class SNAPIClientException : Exception
{
	public SNAPIClientException(string errorMessage) : base(errorMessage)
	{
	}

	public SNAPIClientException(string errorMessage, Exception innerException) : base(errorMessage, innerException)
	{ }
}

