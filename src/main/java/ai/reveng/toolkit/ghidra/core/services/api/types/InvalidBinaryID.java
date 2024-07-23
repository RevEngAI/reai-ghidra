package ai.reveng.toolkit.ghidra.core.services.api.types;



/**
 * Exception thrown when a binary ID is invalid or not accessible under a certain config
 */
public class InvalidBinaryID extends Exception{
    private final BinaryID binaryID;
    private final ApiInfo config;

    public InvalidBinaryID(BinaryID binaryID, ApiInfo config) {
        super("Binary ID " + binaryID + " is invalid under config " + config);
        this.binaryID = binaryID;
        this.config = config;
    }
};
