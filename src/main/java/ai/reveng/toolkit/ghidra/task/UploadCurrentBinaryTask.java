package ai.reveng.toolkit.ghidra.task;

import java.io.File;
import java.io.IOException;

import org.json.JSONException;

import ai.reveng.toolkit.exceptions.RE_AIApiException;
import ai.reveng.toolkit.ghidra.RE_AIPluginPackage;
import ai.reveng.toolkit.ghidra.RE_AIToolkitHelper;
import ghidra.app.util.exporter.BinaryExporter;
import ghidra.app.util.exporter.ExporterException;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class UploadCurrentBinaryTask extends Task {
	private TaskCallback<String> callback;

	public UploadCurrentBinaryTask(TaskCallback<String> callback) {
		super(RE_AIPluginPackage.WINDOW_PREFIX + "Upload Binary", true, false, false);
		this.callback = callback;
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
	public void run(TaskMonitor monitor) throws CancelledException {
		// check we have all the information we need, i.e. that the user config is
		// correct
		// export the current program as a binary
		Program program = RE_AIToolkitHelper.getInstance().getFlatAPI().getCurrentProgram();
		if (program == null) {
			callback.onTaskError(new Exception("No program loaded"));
			return;
		}

		String modelName = null;
		try {
			modelName = RE_AIToolkitHelper.getInstance().getClient().getConfig().getModel().toString();
		} catch (NullPointerException e) {
			callback.onTaskError(new Exception(
					"Could not read model name, please make sure you have setup your ghidra client using the configuration window"));
		}
		String isa = RE_AIToolkitHelper.getInstance().getFlatAPI().getCurrentProgram().getLanguage().getProcessor()
				.toString();
		String os = inferOSFromFormat(
				RE_AIToolkitHelper.getInstance().getFlatAPI().getCurrentProgram().getExecutableFormat().toUpperCase());
		String fileType = inferTypeFromFormat(
				RE_AIToolkitHelper.getInstance().getFlatAPI().getCurrentProgram().getExecutableFormat().toUpperCase());

		try {
			String hash = RE_AIToolkitHelper.getInstance().getClient().analyse(
					RE_AIToolkitHelper.getInstance().getFlatAPI().getProgramFile().getAbsolutePath(), modelName, isa,
					os, RE_AIToolkitHelper.getInstance().getFlatAPI().getProgramFile().getName().toString(), fileType,
					false, "\"\"");
			callback.onTaskCompleted(hash);
		} catch (JSONException | RE_AIApiException e) {
			callback.onTaskError(e);
		}

	}

}
