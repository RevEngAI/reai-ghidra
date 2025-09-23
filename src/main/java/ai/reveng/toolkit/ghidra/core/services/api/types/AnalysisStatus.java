package ai.reveng.toolkit.ghidra.core.services.api.types;

public enum AnalysisStatus {
    Complete("Complete"),
    Error("Error"),
    Processing("Processing"),
    Queued("Queued"),
    // All is only for searching, never an actual analysis status
    All("All");
    private final String status;

    AnalysisStatus(final String status) {
        this.status = status;
    }
}
