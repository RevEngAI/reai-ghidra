package ai.reveng.toolkit.ghidra.core.services.function.export;

import java.util.List;

import org.json.JSONObject;
import org.json.JSONArray;

import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;

public class ExportFunctionBoundariesServiceImpl implements ExportFunctionBoundariesService {
	private FunctionManager fm;
	private Program currentProgram;
	
	public ExportFunctionBoundariesServiceImpl(PluginTool tool) {
		ProgramManager programManager = tool.getService(ProgramManager.class);
		currentProgram = programManager.getCurrentProgram();
		
		if (currentProgram == null)
			return;
		
		initFunctionManager();
	}
	
	public void initFunctionManager() {
		this.fm = currentProgram.getFunctionManager();
	}

	@Override
	public JSONObject getFunctionAt(Address entry) {
		initFunctionManager();
		
		Function f = fm.getFunctionAt(entry);
		
		JSONObject jFunctionBoundaries = new JSONObject();
		jFunctionBoundaries.put("name", f.getName());
		jFunctionBoundaries.put("start", f.getEntryPoint().toString());
		jFunctionBoundaries.put("end", f.getBody().getMaxAddress().toString());
		
		return jFunctionBoundaries;
	}

	@Override
	public JSONObject getFunctions() {
		initFunctionManager();
		
		JSONObject jFunctions = new JSONObject();
		
		JSONArray fArray = new JSONArray();
		for (Function f : fm.getFunctions(true)) {
			fArray.put(getFunctionAt(f.getEntryPoint()));
		}
		
		jFunctions.put("function_boundaries", fArray);
		return jFunctions;
	}

}
