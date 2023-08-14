package ai.reveng.reait.ghidra.task;

import org.json.JSONException;

import ai.reveng.reait.exceptions.REAIApiException;
import ai.reveng.reait.ghidra.REAITHelper;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class DeleteBinaryTask extends Task{
	private TaskCallback<String> callback;
	
	private String binHash;

	public DeleteBinaryTask(TaskCallback<String> callback, String binHash) {
		super("Delete Binary", true, false, false);
		this.callback = callback;
		this.binHash = binHash;
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		try {
			String result = REAITHelper.getInstance().getClient().delete(binHash);
			callback.onTaskCompleted(result);
		} catch (JSONException | REAIApiException e) {
			callback.onTaskError(e);
		}
		
	}
}
