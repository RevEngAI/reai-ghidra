package ai.reveng.reait.ghidra.task;

import org.json.JSONArray;
import org.json.JSONException;

import ai.reveng.reait.exceptions.REAIApiException;
import ai.reveng.reait.ghidra.REAITHelper;
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
			JSONArray result = REAITHelper.getInstance().getClient().getBinaryEmbeddings(binHash, model);
			callback.onTaskCompleted(result);
		} catch (JSONException | REAIApiException e) {
			callback.onTaskError(e);
		}

	}
}
