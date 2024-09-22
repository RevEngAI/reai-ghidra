package ai.reveng.toolkit.ghidra.core.services.api.types;

public class InvalidAPIInfoException extends Exception {
    public InvalidAPIInfoException(String message) {
        super(message);
    }

    public InvalidAPIInfoException(String message, Throwable cause) {
        super(message, cause);
    }
}
