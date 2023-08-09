package ai.reveng.reait.ghidra;

import ai.reveng.reait.REAITClient;
import ghidra.util.task.TaskMonitor;

public final class REAITHelper {
	private static REAITHelper instance;
	private static TaskMonitor taskMonitor;
	
	private REAITClient client;
	
	private REAITHelper() {
		return;
	}
	
	public static REAITHelper getInstance() {
		if (instance == null) {
			instance = new REAITHelper();
		}
		
		return instance;
	}

	public REAITClient getClient() {
		return client;
	}

	public void setClient(REAITClient client) {
		this.client = client;
	}

	public static TaskMonitor getTaskMonitor() {
		return taskMonitor;
	}

	public static void setTaskMonitor(TaskMonitor taskMonitor) {
		REAITHelper.taskMonitor = taskMonitor;
	}
}
