package ai.reveng.reait.ghidra.actions;

import java.util.Vector;

import org.json.JSONArray;
import org.json.JSONObject;

import ai.reveng.reait.exceptions.REAIApiException;
import ai.reveng.reait.ghidra.REAITHelper;
import ai.reveng.reait.ghidra.task.GetBinaryEmbeddingsTask;
import ai.reveng.reait.ghidra.task.TaskCallback;
import docking.ActionContext;
import docking.action.DockingAction;
import ghidra.app.context.ListingActionContext;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.util.FunctionSignatureFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;

public class RenameFunctionFromEmbeddingsAction extends DockingAction {
	private TaskCallback<JSONArray> getBinaryEmbeddingsCallback;

	private JSONArray embeddings;
	private Function functionUnderReview;

	public RenameFunctionFromEmbeddingsAction(String name, String owner) {
		super(name, owner);

		getBinaryEmbeddingsCallback = new TaskCallback<JSONArray>() {

			@Override
			public void onTaskError(Exception e) {
				Msg.showError(name, null, "", e.getMessage());

			}

			@Override
			public void onTaskCompleted(JSONArray result) {
				embeddings = result;

				// find the embedding for this function
				for (int i = 0; i < embeddings.length(); i++) {
					JSONObject embedding = embeddings.getJSONObject(i);
					if (embedding.getString("name").equals(functionUnderReview.getName())) {
						// send the request
						JSONArray functionEmbeddingsJson = new JSONArray(embedding.getJSONArray("embedding"));
						Vector<Double> functionEmbeddings = new Vector<Double>();
						for (int j = 0; j < functionEmbeddingsJson.length(); j++) {
							functionEmbeddings.add(functionEmbeddingsJson.getDouble(j));
						}
						System.out.println("Got embeddings for: " + embedding.getString("name"));
						try {
							REAITHelper.getInstance().getClient().ann_symbols(0.2, 5, "", functionEmbeddings);
						} catch (REAIApiException e) {
							Msg.showError(name, null, "ANN Error", e.getMessage());
						}
					}
				}
			}
		};
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		if (context instanceof ListingActionContext) {
			ListingActionContext lac = (ListingActionContext) context;
			ProgramLocation location = lac.getLocation();
			if (location instanceof FunctionSignatureFieldLocation) {
				return true;
			}
		}
		return false;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		if (context instanceof ListingActionContext) {

			ListingActionContext lac = (ListingActionContext) context;
			ProgramLocation location = lac.getLocation();

			if (location != null) {
				Address addr = location.getAddress();
				FunctionManager functionManager = lac.getProgram().getFunctionManager();
				Function function = functionManager.getFunctionContaining(addr);

				if (function != null) {
					functionUnderReview = function;
					// Get all of the embeddings for this binary
					String selectedHash = REAITHelper.getInstance().getClient().getConfig().getAnalysisHash();
					String selectedModel = REAITHelper.getInstance().getClient().getConfig().getModel().toString();
					Task task = new GetBinaryEmbeddingsTask(getBinaryEmbeddingsCallback, selectedHash, selectedModel);
					TaskLauncher.launch(task);
				}
			}
		}
	}

}
