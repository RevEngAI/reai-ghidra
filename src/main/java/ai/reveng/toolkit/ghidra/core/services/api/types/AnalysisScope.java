package ai.reveng.toolkit.ghidra.core.services.api.types;

public enum AnalysisScope {
    PRIVATE("PRIVATE"),
    PUBLIC("PUBLIC"),
    ALL("ALL");

    public final String scope;
    AnalysisScope(final String scope) {
        this.scope = scope;
    }
}
