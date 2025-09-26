package ai.reveng.toolkit.ghidra.core.services.function.export;

import org.json.JSONArray;
import org.json.JSONObject;

import ai.reveng.toolkit.ghidra.plugins.AnalysisManagementPlugin;
import ghidra.framework.plugintool.ServiceInfo;
import ghidra.program.model.address.Address;

@ServiceInfo(defaultProvider = AnalysisManagementPlugin.class, description = "Export Function Boundaries for passing to the binary analysis server")
public interface ExportFunctionBoundariesService {
	/**
	 * Return the boundaries for a single function
	 * 
	 * @param entry
	 * @return
	 */
	public JSONObject getFunctionAt(Address entry);

	/**
	 * Return a list of function boundary info objects for the whole binary
	 * 
	 * @return
	 */
	public JSONObject getFunctions();
	
	/**
	 * Return an array of functions boundaries for insertion to a symbols object
	 * @return
	 */
	public JSONArray getFunctionsArray();

    /**
     * Return a hash of the function boundaries for change detection
     * Note that this algorithm must match that used on the API server side!
     * @return
     */
    public String getFunctionBoundariesHash();
}
