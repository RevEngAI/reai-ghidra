package ai.reveng.toolkit.ghidra.core.services.importer;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;

import org.json.JSONObject;
import org.json.JSONTokener;

import ai.reveng.toolkit.ghidra.ReaiPluginPackage;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

public class AnalysisImportServiceImpl implements AnalysisImportService {
	private PluginTool tool;
	private FunctionManager fm;

	private boolean isReady;

	public AnalysisImportServiceImpl(PluginTool tool) {
		this.tool = tool;
		isReady = false;
	}

	/**
	 * This is done separately to the constructor as current program will be null if
	 * the plugin is being configured without a binary loaded
	 */
	private void init() {
		ProgramManager programManager = tool.getService(ProgramManager.class);
		Program currentProgram = programManager.getCurrentProgram();
		fm = currentProgram.getFunctionManager();
		isReady = true;
	}

	@Override
	public void importFromJSON(File jsonFile) {
		if (!isReady)
			init();
		
		InputStream is;
		try {
			is = new FileInputStream(jsonFile);
			JSONTokener tokener = new JSONTokener(is);
	        JSONObject object = new JSONObject(tokener);
	        
	        tool.getOptions("Preferences").setLong(ReaiPluginPackage.OPTION_KEY_BINID, object.getLong("binary_id"));
		} catch (FileNotFoundException e) {
			Msg.showError(this, null, ReaiPluginPackage.WINDOW_PREFIX + "Analysis Import", e.getMessage());
		}
	}

}
