package ai.reveng.toolkit.ghidra.actions;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;

public class AskForFunctionExplanation extends DockingAction {

    private PluginTool tool;

    public AskForFunctionExplanation(Plugin plugin) {
        super("CustomDecompilerAction", plugin.getName());
        this.tool = plugin.getTool();
        setPopupMenuData(new MenuData(new String[] {"Explain this function" }, null, "RevEng.AI"));
    }

    @Override
    public boolean isEnabledForContext(ActionContext context) {
        if (!(context instanceof DecompilerActionContext)) {
            return false;
        }
        DecompilerActionContext decompilerContext = (DecompilerActionContext) context;
        // You can refine when your action is enabled. For now, it's always enabled.
        return true;
    }

    @Override
    public void actionPerformed(ActionContext context) {
        if (!(context instanceof DecompilerActionContext)) {
            return;
        }
        
        
    }
}
