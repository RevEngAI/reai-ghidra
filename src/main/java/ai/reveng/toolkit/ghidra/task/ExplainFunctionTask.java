package ai.reveng.toolkit.ghidra.task;

import org.json.JSONException;

import ai.reveng.toolkit.exceptions.RE_AIApiException;
import ai.reveng.toolkit.ghidra.RE_AIPluginPackage;
import ai.reveng.toolkit.ghidra.RE_AIToolkitHelper;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class ExplainFunctionTask extends Task {
	private TaskCallback<String> callback;

	private String decompiledFunction;

	public ExplainFunctionTask(TaskCallback<String> callback, String decompiledFunction) {
		super(RE_AIPluginPackage.WINDOW_PREFIX+"Explain Function", true, false, false);
		this.callback = callback;
		this.decompiledFunction = decompiledFunction;
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		try {
			String result = RE_AIToolkitHelper.getInstance().getClient().explain(decompiledFunction);
			callback.onTaskCompleted(result);
		} catch (JSONException | RE_AIApiException e) {
			callback.onTaskError(e);
		}

	}
}
