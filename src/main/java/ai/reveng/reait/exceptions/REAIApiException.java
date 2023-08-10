package ai.reveng.reait.exceptions;

/**
 * Exception for when the server returns an error for an API Key
 */
public class REAIApiException extends Exception {
	public REAIApiException(String message) {
		super(message);
	}
}
