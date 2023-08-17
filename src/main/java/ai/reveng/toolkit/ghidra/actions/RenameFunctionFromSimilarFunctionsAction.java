package ai.reveng.toolkit.ghidra.actions;

import ai.reveng.toolkit.ghidra.component.RenameFunctionDockableDialog;
import docking.ActionContext;
import docking.action.DockingAction;
import ghidra.app.context.ListingActionContext;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.util.FunctionSignatureFieldLocation;
import ghidra.program.util.ProgramLocation;

public class RenameFunctionFromSimilarFunctionsAction extends DockingAction {
	private PluginTool plugin;

	public RenameFunctionFromSimilarFunctionsAction(String name, PluginTool plugin) {
		super(name, plugin.getName());
		this.plugin = plugin;
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
					RenameFunctionDockableDialog configure = new RenameFunctionDockableDialog(function);
					plugin.showDialog(configure);
				}
			}
		}
	}

}
