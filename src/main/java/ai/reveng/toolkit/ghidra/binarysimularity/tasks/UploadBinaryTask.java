package ai.reveng.toolkit.ghidra.binarysimularity.tasks;

import java.io.File;

import ai.reveng.toolkit.ghidra.core.services.api.AnalysisOptions;
import ai.reveng.toolkit.ghidra.core.services.api.ApiService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class UploadBinaryTask extends Task {
	private final File bin;
	private PluginTool tool;

	public UploadBinaryTask(PluginTool tool, File bin) {
		super("Uploading Binary" + bin.getAbsolutePath(), true, true, true);
		this.bin = bin;
		this.tool = tool;
	}

	private String inferOSFromFormat(String format) {
		if (format.contains("PE")) {
			return "Windows";
		} else if (format.contains("ELF")) {
			return "Linux";
		} else if (format.contains("MACH-O")) {
			return "MacOS";
		} else {
			return "Unknown";
		}
	}

	private String inferTypeFromFormat(String format) {
		if (format.contains("PE")) {
			return "PE";
		} else if (format.contains("ELF")) {
			return "ELF";
		} else if (format.contains("MACH-O")) {
			return "Mach-O";
		} else {
			return "Unknown";
		}
	}

	@Override
	public void run(TaskMonitor monitor) {
		System.out.println("Uploading " + bin.getName());
		monitor.setMessage("Uploading " + bin.getName());
//		tool.getService(ApiService.class).analyse(bin.getAbsolutePath(), , new AnalysisOptions.Builder().build());
	}

}
