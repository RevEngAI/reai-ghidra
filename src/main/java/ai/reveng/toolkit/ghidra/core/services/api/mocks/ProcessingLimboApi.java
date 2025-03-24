package ai.reveng.toolkit.ghidra.core.services.api.mocks;

import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisID;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisStatus;
import ai.reveng.toolkit.ghidra.core.services.api.types.BinaryID;

/**
 * An API mock to simulate a server that is never finished with processing a binary.
 */
public class ProcessingLimboApi extends UnimplementedAPI {
    private int logCounter = 0;
    @Override
    public AnalysisStatus status(BinaryID binID) {
        return AnalysisStatus.Processing;
    }

    @Override
    public String getAnalysisLogs(AnalysisID analysisID) {
        return "Analysis Logs: " + logCounter++;
    }
}
