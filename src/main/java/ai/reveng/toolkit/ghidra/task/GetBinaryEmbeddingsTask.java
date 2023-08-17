package ai.reveng.toolkit.ghidra.task;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

import org.json.JSONArray;
import org.json.JSONException;

import ai.reveng.toolkit.exceptions.RE_AIApiException;
import ai.reveng.toolkit.ghidra.RE_AIPluginPackage;
import ai.reveng.toolkit.ghidra.RE_AIToolkitHelper;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class GetBinaryEmbeddingsTask extends Task {
	private TaskCallback<JSONArray> callback;
	private String binHash;
	private String model;

	public GetBinaryEmbeddingsTask(TaskCallback<JSONArray> callback, String binHash, String model) {
		super(RE_AIPluginPackage.WINDOW_PREFIX+"Get Binary Embeddings", true, false, false);
		this.callback = callback;
		this.binHash = binHash;
		this.model = model;
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		try {
			JSONArray result = null;
			File embeddingsFile = new File(RE_AIToolkitHelper.getInstance().getReaiDir()+"/"+RE_AIToolkitHelper.getInstance().getClient().getConfig().getAnalysisHash()+".json");
			// check if we already have the embeddings for this binary stored locally
			if (embeddingsFile.exists()) {
				try (BufferedReader reader = new BufferedReader(new FileReader(embeddingsFile))) {
					StringBuffer jsonContent = new StringBuffer();
					String line;
					while ((line = reader.readLine()) != null) {
						jsonContent.append(line);
					}
					
					result = new JSONArray(jsonContent.toString());
					System.out.println("Read embeddings from file: " + embeddingsFile.getAbsolutePath());
				} catch (IOException e) {
					callback.onTaskError(e);
				}
			} else {
				result = RE_AIToolkitHelper.getInstance().getClient().getBinaryEmbeddings(binHash, model);
				try (FileWriter fileWriter = new FileWriter(embeddingsFile)) {
					fileWriter.write(result.toString());
					System.out.println("Wrote embeddings to file: " + embeddingsFile.getAbsolutePath());
				} catch (IOException e) {
					callback.onTaskError(e);
				}
				
			}
			callback.onTaskCompleted(result);
		} catch (JSONException | RE_AIApiException e) {
			callback.onTaskError(e);
		}

	}
}
