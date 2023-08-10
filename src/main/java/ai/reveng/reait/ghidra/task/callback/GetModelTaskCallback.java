package ai.reveng.reait.ghidra.task.callback;

import java.util.Vector;

/**
 * Allows a UI component to receive a list of models from a GetModels request
 * 
 * @see GetREAIModelsTask
 */
public interface GetModelTaskCallback {
	void onTaskCompleted(Vector<String> results);
	void onTaskError(Exception e);
}
