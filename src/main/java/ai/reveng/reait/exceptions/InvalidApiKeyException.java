package ai.reveng.reait.exceptions;

/**
 * Exception for when the server returns an error for an API Key
 */
public class InvalidApiKeyException extends Exception {
	public InvalidApiKeyException(String message) {
		super(message);
	}
}
