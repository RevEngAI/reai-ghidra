package ai.reveng.reait.ghidra.actions;

import java.io.File;
import java.io.IOException;

import ai.reveng.reait.ghidra.REAITHelper;
import docking.ActionContext;
import docking.action.DockingAction;
import ghidra.app.util.exporter.BinaryExporter;
import ghidra.app.util.exporter.ExporterException;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class UploadCurrentBinaryAction extends DockingAction {

	public UploadCurrentBinaryAction(String name, String owner) {
		super(name, owner);
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
	public void actionPerformed(ActionContext context) {
		// check we have all the information we need, i.e. that the user config is correct
		// export the current program as a binary
		Program program = REAITHelper.getInstance().getFlatAPI().getCurrentProgram();
        if (program == null) {
            Msg.showInfo(context, null, "Upload Current Binary", "No program loaded.");
            return;
        }

        BinaryExporter exporter = new BinaryExporter();
        String path = REAITHelper.getInstance().getExportBinPath();
        File outputFile = new File(path);
        // make sure the directory exists
        outputFile.getParentFile().mkdirs();
        try {
			exporter.export(outputFile, program, program.getMemory().getAllInitializedAddressSet(), TaskMonitor.DUMMY);
//			Msg.showInfo(context, null, "Upload Current Binary", "Exported to: " + outputFile.getAbsolutePath());
		} catch (IOException | ExporterException e) {
			Msg.showError(outputFile, null, "Upload Current Binary", "Error exporting binary: "+e.getMessage());
			return;
		}
        
        String modelName = null;
        try {
        	modelName = REAITHelper.getInstance().getClient().getConfig().getModel().toString();
        } catch (NullPointerException e) {
        	Msg.showError(outputFile, null, "Configuration Error", "Could not read model name, please make sure you have setup your ghidra client using the configuration window");;
        }
        String isa = REAITHelper.getInstance().getFlatAPI().getCurrentProgram().getLanguage().getProcessor().toString();
        String os = inferOSFromFormat(REAITHelper.getInstance().getFlatAPI().getCurrentProgram().getExecutableFormat().toUpperCase()).toLowerCase();
        String fileType = inferTypeFromFormat(REAITHelper.getInstance().getFlatAPI().getCurrentProgram().getExecutableFormat().toUpperCase()).toLowerCase();
        
        REAITHelper.getInstance().getClient().analyse(path, modelName, isa, os, fileType, false, null);
		
	}

}
