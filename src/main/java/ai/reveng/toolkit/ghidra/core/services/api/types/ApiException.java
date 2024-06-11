package ai.reveng.toolkit.ghidra.core.services.api.types;

/*
    * Exception class for errors that result from incorrect usage of the reveng API
    * The client implementations of specific endpoints should subclass this exception
    * for their respective specific failures, so any user of the API can handle specific failure modes
 */
public class ApiException extends Exception {
    private final int errorcode;

    public ApiException(int errorcode, String message) {
        super(message);
        this.errorcode = errorcode;
    }
}
