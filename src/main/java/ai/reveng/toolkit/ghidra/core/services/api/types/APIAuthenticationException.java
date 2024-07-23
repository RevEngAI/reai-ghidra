package ai.reveng.toolkit.ghidra.core.services.api.types;

public class APIAuthenticationException extends RuntimeException{
    public APIAuthenticationException(String message) {
        super(message);
    }
}
