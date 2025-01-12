package ai.reveng.toolkit.ghidra.core.services.api.types.exceptions;

public class APIConflictException extends RuntimeException{
    public APIConflictException(String message) {
        super(message);
    }
}
