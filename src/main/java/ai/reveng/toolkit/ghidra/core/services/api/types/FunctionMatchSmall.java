package ai.reveng.toolkit.ghidra.core.services.api.types;


/**
 * For some reason the Batch Symbol ANN for function IDs
 * returns a different kind of data layout {@link FunctionMatchSmall}
 * than the Batch Symbol ANN for a BinaryID. {@link FunctionMatch}
 *
 */
public record FunctionMatchSmall() {
}
