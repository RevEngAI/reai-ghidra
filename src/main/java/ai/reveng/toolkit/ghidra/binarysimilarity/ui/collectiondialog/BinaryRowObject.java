package ai.reveng.toolkit.ghidra.binarysimilarity.ui.collectiondialog;

import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisResult;

public class BinaryRowObject {
    AnalysisResult analysisResult;
    boolean include;
    public BinaryRowObject(AnalysisResult analysisResult, boolean include) {
        this.analysisResult = analysisResult;
        this.include = include;
    }

    public AnalysisResult analysisResult() {
        return analysisResult;
    }
    public boolean include() {
        return include;
    }
    public void setInclude(boolean include) {
        this.include = include;
    }
}
