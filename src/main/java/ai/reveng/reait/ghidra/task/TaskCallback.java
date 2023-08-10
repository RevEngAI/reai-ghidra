package ai.reveng.reait.ghidra.task;

public interface TaskCallback<T> {
	void onTaskCompleted(T result);
	void onTaskError(Exception e);
}
