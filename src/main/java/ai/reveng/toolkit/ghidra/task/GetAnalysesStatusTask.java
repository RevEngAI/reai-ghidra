package ai.reveng.toolkit.ghidra.task;

import org.json.JSONArray;
import org.json.JSONException;

import ai.reveng.toolkit.exceptions.RE_AIApiException;
import ai.reveng.toolkit.ghidra.RE_AIPluginPackage;
import ai.reveng.toolkit.ghidra.RE_AIToolkitHelper;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class GetAnalysesStatusTask extends Task {
	private TaskCallback<JSONArray> callback;

	public GetAnalysesStatusTask(TaskCallback<JSONArray> callback) {
		super(RE_AIPluginPackage.WINDOW_PREFIX+"Get Status", true, false, false);
		this.callback = callback;
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		try {
			JSONArray result = RE_AIToolkitHelper.getInstance().getClient().status();
			callback.onTaskCompleted(result);
		} catch (JSONException | RE_AIApiException e) {
			callback.onTaskError(e);
		}

	}
}