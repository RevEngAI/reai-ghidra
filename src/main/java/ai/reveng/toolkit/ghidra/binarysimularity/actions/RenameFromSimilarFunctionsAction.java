package ai.reveng.toolkit.ghidra.binarysimularity.actions;

import ai.reveng.toolkit.ghidra.binarysimularity.ui.functionsimularity.FunctionSimularityDockableDialog;
import ai.reveng.toolkit.ghidra.core.services.api.ApiService;
import docking.ActionContext;
import docking.action.DockingAction;
import ghidra.app.context.ListingActionContext;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.util.FunctionSignatureFieldLocation;
import ghidra.program.util.ProgramLocation;

public class RenameFromSimilarFunctionsAction extends DockingAction {
	private PluginTool tool;

	public RenameFromSimilarFunctionsAction(String name, PluginTool plugin) {
		super(name, plugin.getName());
		this.tool = plugin;
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		if (context instanceof ListingActionContext) {
			ListingActionContext lac = (ListingActionContext) context;
			ProgramLocation location = lac.getLocation();
			if (location instanceof FunctionSignatureFieldLocation) {
				return true;
			}
		}
		return false;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		if (context instanceof ListingActionContext) {

			ListingActionContext lac = (ListingActionContext) context;
			ProgramLocation location = lac.getLocation();

			if (location != null) {
				Address addr = location.getAddress();
				FunctionManager functionManager = lac.getProgram().getFunctionManager();
				Function function = functionManager.getFunctionContaining(addr);

				if (function != null) {
					FunctionSimularityDockableDialog renameDialogue = new FunctionSimularityDockableDialog(function, tool);
					tool.showDialog(renameDialogue);
				}
			}
		}
	}

}