package ai.reveng.toolkit.ghidra.actions;

import ai.reveng.toolkit.ghidra.task.TaskCallback;
import ai.reveng.toolkit.ghidra.task.UploadCurrentBinaryTask;
import docking.ActionContext;
import docking.action.DockingAction;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;

public class UploadCurrentBinaryAction extends DockingAction {
	private TaskCallback<String> callback;

	public UploadCurrentBinaryAction(String name, String owner) {
		super(name, owner);

		this.callback = new TaskCallback<String>() {

			@Override
			public void onTaskError(Exception e) {
				// TODO Auto-generated method stub

			}

			@Override
			public void onTaskCompleted(String result) {
				// TODO Auto-generated method stub

			}
		};
	}

	@Override
	public void actionPerformed(ActionContext context) {
		Task task = new UploadCurrentBinaryTask(callback);
		TaskLauncher.launch(task);

	}

}
