package ai.reveng.toolkit.ghidra.core.services.api.types.exceptions;

/**
 * This exception indicates an unexpected case of the API returning an authentication error
 * this can happen when attempting to retrieve information about a private analysis ID owned by a different account
 */
public class APIAuthenticationException extends RuntimeException{
    public APIAuthenticationException(String message) {
        super(message);
    }
}
