package ai.reveng.toolkit.ghidra.task;

import org.json.JSONArray;
import org.json.JSONException;

import ai.reveng.toolkit.exceptions.RE_AIApiException;
import ai.reveng.toolkit.ghidra.RE_AIToolkitHelper;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class GetBinaryEmbeddingsTask extends Task {
	private TaskCallback<JSONArray> callback;
	private String binHash;
	private String model;

	public GetBinaryEmbeddingsTask(TaskCallback<JSONArray> callback, String binHash, String model) {
		super("Get Binary Embeddings", true, false, false);
		this.callback = callback;
		this.binHash = binHash;
		this.model = model;
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		try {
			JSONArray result = RE_AIToolkitHelper.getInstance().getClient().getBinaryEmbeddings(binHash, model);
			callback.onTaskCompleted(result);
		} catch (JSONException | RE_AIApiException e) {
			callback.onTaskError(e);
		}

	}
}
