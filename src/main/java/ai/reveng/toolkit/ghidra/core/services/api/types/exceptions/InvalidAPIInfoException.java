package ai.reveng.toolkit.ghidra.core.services.api.types.exceptions;

public class InvalidAPIInfoException extends Exception {
    public InvalidAPIInfoException(String message) {
        super(message);
    }

    public InvalidAPIInfoException(String message, Throwable cause) {
        super(message, cause);
    }
}
