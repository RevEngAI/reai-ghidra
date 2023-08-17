package ai.reveng.toolkit.ghidra.task;

/**
 * Interface for defining callbacks for UI components to get task results
 * 
 * @param <T> Type of result returned
 */
public interface TaskCallback<T> {
	/**
	 * Inform the caller that the task has been completed
	 * 
	 * @param result data returned to calling component
	 */
	void onTaskCompleted(T result);

	/**
	 * Inform the caller that there was an error with the task
	 * 
	 * @param e exception for caller to handle
	 */
	void onTaskError(Exception e);
}
