package ai.reveng.reait.ghidra.task.callback;

import java.util.Vector;

/**
 * Allows a UI component to receive a list of models from a GetModels request
 * 
 * @see GetREAIModelsTask
 */
public interface GetModelTaskCallback {
	/**
	 * Pass the list of model names back to the calling component
	 * @param results list of model names in the form <model>-<version>
	 */
	void onTaskCompleted(Vector<String> results);
	/**
	 * Inform the caller that an error has occurred and allow them to handle it
	 * @param e generic exception
	 */
	void onTaskError(Exception e);
}
