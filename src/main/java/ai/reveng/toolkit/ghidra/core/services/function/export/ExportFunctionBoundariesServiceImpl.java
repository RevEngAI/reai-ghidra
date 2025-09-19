package ai.reveng.toolkit.ghidra.core.services.function.export;

import org.json.JSONObject;
import org.json.JSONArray;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

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
	public JSONObject getFunctionAt(Address entry) {
		if (!isReady)
			init();

		Function f = fm.getFunctionAt(entry);

		JSONObject jFunctionBoundaries = new JSONObject();
		jFunctionBoundaries.put("name", f.getName());
		jFunctionBoundaries.put("start_addr", f.getEntryPoint().toString("0x"));
		jFunctionBoundaries.put("end_addr", f.getBody().getMaxAddress().toString("0x"));

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

		jFunctions.put("functions", fArray);
		return jFunctions;
	}
	
	@Override
	public JSONArray getFunctionsArray() {
		if (!isReady)
			init();
		
		JSONArray fArray = new JSONArray();
		for (Function f : fm.getFunctions(true)) {
			fArray.put(getFunctionAt(f.getEntryPoint()));
		}
		return fArray;
	}

    @Override
    public String getFunctionBoundariesHash() {
        if (!isReady)
            init();

        // Collect all function boundaries into a list
        List<JSONObject> boundaries = new ArrayList<>();
        for (Function f : fm.getFunctions(true)) {
            boundaries.add(getFunctionAt(f.getEntryPoint()));
        }

        // Sort the boundaries by start address (convert hex string to long for proper sorting)
        boundaries.sort(Comparator.comparingLong(b -> Long.parseUnsignedLong(
            b.getString("start_addr").substring(2), 16)));

        // Create a formatted string representation of the boundaries
        StringBuilder boundariesStr = new StringBuilder();
        for (int i = 0; i < boundaries.size(); i++) {
            JSONObject b = boundaries.get(i);
            if (i > 0) {
                boundariesStr.append(",");
            }

            // Convert hex addresses to integer representation
            String startAddrHex = b.getString("start_addr");
            String endAddrHex = b.getString("end_addr");
            long startAddrInt = Long.parseUnsignedLong(startAddrHex.substring(2), 16);
            long endAddrInt = Long.parseUnsignedLong(endAddrHex.substring(2), 16);

            boundariesStr.append(startAddrInt)
                         .append("-")
                         .append(endAddrInt);
        }

        // Generate SHA-256 hash of the boundaries string
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(boundariesStr.toString().getBytes());

            // Convert to hexadecimal string
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }
}
