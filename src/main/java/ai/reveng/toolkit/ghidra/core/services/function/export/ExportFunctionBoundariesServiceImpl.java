package ai.reveng.toolkit.ghidra.core.services.function.export;

import org.json.JSONObject;
import org.json.JSONArray;

import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;

public class ExportFunctionBoundariesServiceImpl implements ExportFunctionBoundariesService {
	
	private PluginTool tool;
	private FunctionManager fm;
	
	private boolean isReady;
	
	public ExportFunctionBoundariesServiceImpl(PluginTool tool) {
		this.tool = tool;
		isReady = false;
	}
	
	/**
	 * This is done separately to the constructor as current program will be null if the plugin is being configured without a binary loaded
	 */
	private void init() {
		ProgramManager programManager = tool.getService(ProgramManager.class);
		Program currentProgram = programManager.getCurrentProgram();
		fm = currentProgram.getFunctionManager();
		isReady = true;
	}

	@Override
	public JSONObject getFunctionAt(Address entry) {
		if (!isReady)
			init();
		
		Function f = fm.getFunctionAt(entry);
		
		JSONObject jFunctionBoundaries = new JSONObject();
		jFunctionBoundaries.put("name", f.getName());
		jFunctionBoundaries.put("start", f.getEntryPoint().toString());
		jFunctionBoundaries.put("end", f.getBody().getMaxAddress().toString());
		
		return jFunctionBoundaries;
	}

	@Override
	public JSONObject getFunctions() {
		if (!isReady)
			init();
		
		JSONObject jFunctions = new JSONObject();
		
		JSONArray fArray = new JSONArray();
		for (Function f : fm.getFunctions(true)) {
			fArray.put(getFunctionAt(f.getEntryPoint()));
		}
		
		jFunctions.put("function_boundaries", fArray);
		return jFunctions;
	}

}
