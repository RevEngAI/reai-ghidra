package ai.reveng.toolkit.ghidra.task;

import org.json.JSONException;

import ai.reveng.toolkit.exceptions.RE_AIApiException;
import ai.reveng.toolkit.ghidra.RE_AIPluginPackage;
import ai.reveng.toolkit.ghidra.RE_AIToolkitHelper;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class DeleteBinaryTask extends Task {
	private TaskCallback<String> callback;

	private String binHash;

	public DeleteBinaryTask(TaskCallback<String> callback, String binHash) {
		super(RE_AIPluginPackage.WINDOW_PREFIX+"Delete Binary", true, false, false);
		this.callback = callback;
		this.binHash = binHash;
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		try {
			String result = RE_AIToolkitHelper.getInstance().getClient().delete(binHash);
			callback.onTaskCompleted(result);
		} catch (JSONException | RE_AIApiException e) {
			callback.onTaskError(e);
		}

	}
}
