package ai.reveng.reait.ghidra.task;

import java.io.File;
import java.io.IOException;

import org.json.JSONException;

import ai.reveng.reait.exceptions.REAIApiException;
import ai.reveng.reait.ghidra.REAITHelper;
import ghidra.app.util.exporter.BinaryExporter;
import ghidra.app.util.exporter.ExporterException;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class UploadCurrentBinaryTask extends Task {
	private TaskCallback<String> callback;

	public UploadCurrentBinaryTask(TaskCallback<String> callback) {
		super("Upload Binary", true, false, false);
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
		Program program = REAITHelper.getInstance().getFlatAPI().getCurrentProgram();
		if (program == null) {
			callback.onTaskError(new Exception("No program loaded"));
			return;
		}

		BinaryExporter exporter = new BinaryExporter();
		String path = REAITHelper.getInstance().getExportBinPath();
		File outputFile = new File(path);
		// make sure the directory exists
		outputFile.getParentFile().mkdirs();
		try {
			exporter.export(outputFile, program, program.getMemory().getAllInitializedAddressSet(), TaskMonitor.DUMMY);
		} catch (IOException | ExporterException e) {
			callback.onTaskError(e);
			return;
		}

		String modelName = null;
		try {
			modelName = REAITHelper.getInstance().getClient().getConfig().getModel().toString();
		} catch (NullPointerException e) {
			callback.onTaskError(new Exception(
					"Could not read model name, please make sure you have setup your ghidra client using the configuration window"));
		}
		String isa = REAITHelper.getInstance().getFlatAPI().getCurrentProgram().getLanguage().getProcessor().toString();
		String os = inferOSFromFormat(
				REAITHelper.getInstance().getFlatAPI().getCurrentProgram().getExecutableFormat().toUpperCase())
				.toLowerCase();
		String fileType = inferTypeFromFormat(
				REAITHelper.getInstance().getFlatAPI().getCurrentProgram().getExecutableFormat().toUpperCase())
				.toLowerCase();

		try {
			String hash = REAITHelper.getInstance().getClient().analyse(path, modelName, isa, os,
					outputFile.getName().toString(), fileType, false, "");
			callback.onTaskCompleted(hash);
		} catch (JSONException | REAIApiException e) {
			callback.onTaskError(e);
		}

	}

}
