package ai.reveng.reait.ghidra.task;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class WriteConfigFileTask extends Task {

	public WriteConfigFileTask() {
		super("Write Config File to disk", true, false, false);
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		// TODO Auto-generated method stub
		
	}

}
