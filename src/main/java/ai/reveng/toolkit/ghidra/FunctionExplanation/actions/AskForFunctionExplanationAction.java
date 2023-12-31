package ai.reveng.toolkit.ghidra.FunctionExplanation.actions;

import ai.reveng.toolkit.ghidra.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.core.services.api.ApiResponse;
import ai.reveng.toolkit.ghidra.core.services.api.ApiService;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

public class AskForFunctionExplanationAction extends DockingAction {

	private PluginTool tool;
	private Function fau;
	private ApiService apiService;

	public AskForFunctionExplanationAction(PluginTool tool) {
		super("CustomDecompilerAction", tool.getName());
		setPopupMenuData(new MenuData(new String[] { "Explain this function" }, ReaiPluginPackage.NAME));
		this.tool = tool;
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DecompilerActionContext)) {
			return false;
		}

		return true;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		if (!(context instanceof DecompilerActionContext)) {
			return;
		}

		DecompilerActionContext decompilerContext = (DecompilerActionContext) context;
		DecompInterface decompiler = new DecompInterface();
		ProgramManager programManager = tool.getService(ProgramManager.class);
		Program currentProgram = programManager.getCurrentProgram();

		decompiler.openProgram(currentProgram);

		boolean initialized = decompiler.openProgram(currentProgram);
		if (!initialized) {
			System.err.println("Failed to initialize DecompInterface");
			return;
		}

		this.fau = currentProgram.getFunctionManager().getFunctionAt(decompilerContext.getAddress());

		if (this.fau == null) {
			System.err.println("No function at given address");
			return;
		}

		DecompileOptions options = decompiler.getOptions();
		if (options == null) {
			options = new DecompileOptions();
			decompiler.setOptions(options);
		}

		int timeout = options.getDefaultTimeout();

		DecompileResults results = decompiler.decompileFunction(this.fau, timeout, null);

		if (!results.decompileCompleted()) {
			System.err.println("Issue decompiling function");
			return;
		}

		ClangTokenGroup decompiledFunction = results.getCCodeMarkup();

		apiService = tool.getService(ApiService.class);
		ApiResponse res = apiService.explain(decompiledFunction.toString());

		int transactionID = currentProgram.startTransaction("Set function pre-comment based on RevEng.ai description");
		fau.setComment(String.format("RevEng.AI Autogenerated\n\n%s", res.getJsonObject().getString("explanation")));
		currentProgram.endTransaction(transactionID, true);
	}
}