package ai.reveng.toolkit.exceptions;

/**
 * Exception for when the server returns an error for an API Key
 */
public class RE_AIApiException extends Exception {
	private static final long serialVersionUID = -4802140967973012578L;

	public RE_AIApiException(String message) {
		super(message);
	}
}
