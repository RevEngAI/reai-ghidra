package ai.reveng.reait.ghidra.actions;

import java.io.File;
import java.io.IOException;

import org.json.JSONException;

import ai.reveng.reait.exceptions.REAIApiException;
import ai.reveng.reait.ghidra.REAITHelper;
import ai.reveng.reait.ghidra.task.TaskCallback;
import ai.reveng.reait.ghidra.task.UploadCurrentBinaryTask;
import ai.reveng.reait.ghidra.task.WriteConfigFileTask;
import docking.ActionContext;
import docking.action.DockingAction;
import ghidra.app.util.exporter.BinaryExporter;
import ghidra.app.util.exporter.ExporterException;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;

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
