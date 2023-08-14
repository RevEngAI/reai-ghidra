package ai.reveng.reait.ghidra.task;

import java.util.List;
import java.util.Vector;

import org.json.JSONException;

import ai.reveng.reait.client.Client;
import ai.reveng.reait.exceptions.REAIApiException;
import ai.reveng.reait.ghidra.REAITHelper;
import ai.reveng.reait.model.ModelInfo;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * Class the allows the GetModels API to be called as a (background) task
 */
public class GetREAIModelsTask extends Task {
	// callback interface used to communicate with the (UI) component
	private TaskCallback<Vector<String>> callback;
	// Users API key
	private String apiKey;
	// Host of the API endpoints
	private String hostname;

	/**
	 * Create a new task for gathering model names from the api
	 * 
	 * @param apikey   users API Key
	 * @param hostname server that hosts the API endpoints
	 * @param callback interface for passing results to frontend
	 */
	public GetREAIModelsTask(String apikey, String hostname, TaskCallback<Vector<String>> callback) {
		super("Get Models", false, false, false);
		this.callback = callback;
		this.apiKey = apikey;
		this.hostname = hostname;
	}

	@Override
	public void run(TaskMonitor monitor) {
		REAITHelper helper = REAITHelper.getInstance();
		monitor.initialize(1);
		if (monitor.isCancelled()) {
			return;
		}
		if (this.apiKey.equals("xxxx-xxxx-xxxx-xxxx") || this.apiKey.equals("")) {
			Msg.showError(this, null, "Invalid API Key", "Please Enter a Valid API Key");
			return;
		}
		monitor.setMessage("Connecting to API server...");
		helper.setClient(new Client(this.apiKey, this.hostname));
		List<ModelInfo> models;
		try {
			models = helper.getClient().getModels(helper.getClient().getConfig().getHost());
		} catch (JSONException | REAIApiException e) {
			this.callback.onTaskError(e);
			return;
		}
		monitor.setMessage("Retreiving available models");
		Vector<String> modelNames = new Vector<String>();
		for (ModelInfo model : models) {
			modelNames.add(model.toString());
		}
		this.callback.onTaskCompleted(modelNames);
	}

}
