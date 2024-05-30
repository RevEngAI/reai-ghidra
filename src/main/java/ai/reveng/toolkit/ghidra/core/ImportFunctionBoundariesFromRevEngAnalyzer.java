package ai.reveng.toolkit.ghidra.core;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ImportFunctionBoundariesFromRevEngAnalyzer extends AbstractAnalyzer {

    public ImportFunctionBoundariesFromRevEngAnalyzer() {
        super("Import Function Boundaries From RevEng", "Imports function boundaries from RevEng", AnalyzerType.BYTE_ANALYZER);
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException {
        return false;
    }
}
