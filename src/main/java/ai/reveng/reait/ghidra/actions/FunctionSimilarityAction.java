package ai.reveng.reait.ghidra.actions;

import ai.reveng.reait.ghidra.REAIToolkitPlugin;
import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.app.plugin.core.function.FunctionPlugin;

public class FunctionSimilarityAction extends ListingContextAction {
	boolean allowExisting = false;
	boolean createThunk = false;
	private REAIToolkitPlugin reaiPlugin;

	public FunctionSimilarityAction(String name, REAIToolkitPlugin plugin) {
		super(name, plugin.getName());
		this.reaiPlugin = plugin;

		setPopupMenuData(new MenuData(new String[] { name }, null, FunctionPlugin.FUNCTION_MENU_SUBGROUP,
				MenuData.NO_MNEMONIC, FunctionPlugin.FUNCTION_SUBGROUP_BEGINNING));

		setEnabled(true);
	}

	@Override
	public void actionPerformed(ListingActionContext context) {
		// TODO
	}

	@Override
	protected boolean isEnabledForContext(ListingActionContext context) {
		return true; // todo
	}
}
