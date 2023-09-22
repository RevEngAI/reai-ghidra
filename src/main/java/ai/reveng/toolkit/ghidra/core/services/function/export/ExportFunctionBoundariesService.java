package ai.reveng.toolkit.ghidra.core.services.function.export;

import org.json.JSONObject;

import ai.reveng.toolkit.ghidra.core.CorePlugin;
import ghidra.framework.plugintool.ServiceInfo;
import ghidra.program.model.address.Address;

@ServiceInfo(defaultProvider = CorePlugin.class, description = "Export Function Boundaries for passing to the binary analysis server")
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
}
