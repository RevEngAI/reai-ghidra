package ai.reveng.toolkit.ghidra.core.services.api.types;

public enum AnalysisStatus {
    Complete("Complete"),
    Error("Error"),
    Processing("Processing"),
    Queued("Queued");

    private final String status;

    AnalysisStatus(final String status) {
        this.status = status;
    }
}
