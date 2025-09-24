package ai.reveng.toolkit.ghidra.binarysimilarity.ui.functionsimilarity;

import ai.reveng.toolkit.ghidra.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.binarysimilarity.BinarySimilarityPlugin;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.context.ProgramLocationActionContext;

public class FunctionSimilarityAction extends DockingAction {
    private final BinarySimilarityPlugin plugin;

    public FunctionSimilarityAction(BinarySimilarityPlugin owner) {
        super("Find Similar Functions", owner.toString());
        plugin = owner;
        setPopupMenuData(new MenuData(new String[]{"Match function"}, ReaiPluginPackage.REVENG_16, ReaiPluginPackage.MENU_GROUP_NAME));
    }

    @Override
    public boolean isEnabledForContext(ActionContext ctx) {
        if (ctx instanceof ProgramLocationActionContext context) {
            var func = context.getProgram().getFunctionManager().getFunctionContaining(context.getAddress());
            var apiService = plugin.getTool().getService(GhidraRevengService.class);
            return func != null
                    && apiService.isKnownProgram(context.getProgram())
                    && apiService.isProgramAnalysed(context.getProgram());
        } else {
            return false;
        }
    }

    /**
     * Trigger the {@link FunctionSimilarityComponent} to be displayed and search for the current function
     * @param context the {@link ActionContext} object that provides information about where and how
     * this action was invoked.
     */
    @Override
    public void actionPerformed(ActionContext context) {
        var programContext = (ProgramLocationActionContext) context;
        var program = programContext.getProgram();
        var function = program.getFunctionManager().getFunctionContaining(programContext.getLocation().getAddress());
        plugin.getFunctionSimilarityComponent().setVisible(true);
        plugin.getFunctionSimilarityComponent().triggerSearchForFunction(function);

    }
}
