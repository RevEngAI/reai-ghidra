package ai.reveng.toolkit.ghidra.core.services.api.mocks;

import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisID;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisStatus;
import ai.reveng.toolkit.ghidra.core.services.api.types.BinaryID;

/**
 * An API mock to simulate a server that is never finished with processing a binary.
 */
public class ProcessingLimboApi extends UnimplementedAPI {

    private final AnalysisStatus status;

    private int logCounter = 0;

    public ProcessingLimboApi() {
        super();
        status = AnalysisStatus.Processing;
    }

    public ProcessingLimboApi(AnalysisStatus status) {
        super();
        this.status = status;
    }

    @Override
    public AnalysisStatus status(BinaryID binID) {
        return status;
    }

    @Override
    public String getAnalysisLogs(AnalysisID analysisID) {
        return "Analysis Logs: " + logCounter++;
    }
}
