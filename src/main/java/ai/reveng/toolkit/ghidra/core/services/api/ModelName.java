package ai.reveng.toolkit.ghidra.core.services.api;

public record ModelName(String modelName) {
    @Override
    public String toString() {
        return modelName;
    }
}
