package ai.reveng.toolkit.ghidra.binarysimularity.tasks;

import ai.reveng.toolkit.ghidra.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.core.services.api.ApiResponse;
import ai.reveng.toolkit.ghidra.core.services.api.ApiService;
import ai.reveng.toolkit.ghidra.core.services.api.types.Binary;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionEmbedding;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * Task that iterates over all functions held by the function manager and
 * renames it based on the most confident result from the RevEng.AI API
 */
public class AutoAnalyseBinary extends Task {
	private ApiService apiService;
	private Program currentProgram;
	private PluginTool tool;

	public AutoAnalyseBinary(PluginTool tool) {
		super(ReaiPluginPackage.WINDOW_PREFIX + "Auto Analysis", true, false, true);
		this.tool = tool;
		apiService = tool.getService(ApiService.class);
		ProgramManager programManager = tool.getService(ProgramManager.class);
		currentProgram = programManager.getCurrentProgram();
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {

		FunctionManager fm = currentProgram.getFunctionManager();

		String currentBinaryHash = currentProgram.getExecutableSHA256();
		long binID = tool.getOptions("Preferences").getLong(ReaiPluginPackage.OPTION_KEY_BINID, 0xff);

		ApiResponse res = apiService.embeddings(binID);

		if (res.getStatusCode() > 299) {
			Msg.showError(fm, null, ReaiPluginPackage.WINDOW_PREFIX + "Auto Analysis",
					res.getJsonObject().get("error"));
			return;
		}

		Binary bin = new Binary(res.getJsonArray(), currentProgram.getImageBase());

		for (Function func : fm.getFunctions(true)) {
			System.out.println("Searching for suitable name for '" + func.getName() + "'");
			FunctionEmbedding fe = bin.getFunctionEmbedding(func.getEntryPoint().toString());
			res = apiService.nearestSymbols(fe.getEmbedding(), currentBinaryHash, 1, null);
		}
	}

}
