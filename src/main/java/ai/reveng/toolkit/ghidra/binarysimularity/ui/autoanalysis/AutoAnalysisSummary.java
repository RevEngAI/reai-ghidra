package ai.reveng.toolkit.ghidra.binarysimularity.ui.autoanalysis;

import java.util.HashMap;
import java.util.Map;

public class AutoAnalysisSummary {
	private Map<String, Integer> summaryStats;
	
	public AutoAnalysisSummary() {
		summaryStats = new HashMap<String, Integer>();
		summaryStats.put("total_analyses", 0);
		summaryStats.put("successful_analyses", 0);
		summaryStats.put("unsuccessful_analyses", 0);
	}
	
	public void incrementStat(String stat) {
		if (!summaryStats.containsKey(stat))
			return;
		
		int newStat = summaryStats.get(stat) + 1;
		summaryStats.put(stat, newStat);
	}
	
	public int getStat(String stat) {
		if (!summaryStats.containsKey(stat))
			return -1;
			
		return summaryStats.get(stat);
	}
}
