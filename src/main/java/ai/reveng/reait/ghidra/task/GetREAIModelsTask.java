package ai.reveng.reait.ghidra.task;

import java.util.List;
import java.util.Vector;

import ai.reveng.reait.client.Client;
import ai.reveng.reait.ghidra.REAITHelper;
import ai.reveng.reait.ghidra.task.callback.GetModelTaskCallback;
import ai.reveng.reait.model.ModelInfo;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class GetREAIModelsTask extends Task {
	private GetModelTaskCallback callback;
	private String apiKey;
	private String hostname;
	
	public GetREAIModelsTask(String apikey, String hostname, GetModelTaskCallback callback) {
		super("Get Models", true, true, true);
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
		List<ModelInfo> models = helper.getClient().getModels();
		monitor.setMessage("Retreiving available models");
		Vector<String> modelNames = new Vector<String>();
		for (ModelInfo model : models) {
			modelNames.add(model.toString());
		}
		this.callback.onTaskCompleted(modelNames);
	}
	
}
