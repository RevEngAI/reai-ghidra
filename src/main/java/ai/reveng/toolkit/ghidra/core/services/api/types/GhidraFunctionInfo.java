package ai.reveng.toolkit.ghidra.core.services.api.types;

import ghidra.program.model.listing.Function;

import java.util.Optional;


/**
 * Combined record of a Ghidra Function and its corresponding FunctionInfo from
 * @param functionInfo
 * @param function
 */
public record GhidraFunctionInfo(
        FunctionInfo functionInfo,
        Function function
) {
}