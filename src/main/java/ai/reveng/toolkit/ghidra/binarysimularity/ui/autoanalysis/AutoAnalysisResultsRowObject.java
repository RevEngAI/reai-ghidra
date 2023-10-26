package ai.reveng.toolkit.ghidra.binarysimularity.ui.autoanalysis;

public class AutoAnalysisResultsRowObject {
	private final String srcSymbol;
	private final String dstSymbol;
	private final boolean successful;
	private final String reason;
	
	public AutoAnalysisResultsRowObject(String srcSymbol, String dstSymbol, boolean successful, String reason) {
		this.srcSymbol = srcSymbol;
		this.dstSymbol = dstSymbol;
		this.successful = successful;
		this.reason = reason;
	}

	public String getSrcSymbol() {
		return srcSymbol;
	}

	public String getDstSymbol() {
		return dstSymbol;
	}

	public boolean isSuccessful() {
		return successful;
	}

	public String getReason() {
		return reason;
	}

}
