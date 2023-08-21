package ai.reveng.toolkit.ghidra.actions;

import ai.reveng.toolkit.ghidra.RE_AIToolkitHelper;
import ai.reveng.toolkit.ghidra.task.ExplainFunctionTask;
import ai.reveng.toolkit.ghidra.task.TaskCallback;
import ai.reveng.toolkit.ghidra.task.UploadCurrentBinaryTask;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;

public class AskForFunctionExplanation extends DockingAction {

    private PluginTool tool;
    private TaskCallback<String> callback;

    public AskForFunctionExplanation(Plugin plugin) {
        super("CustomDecompilerAction", plugin.getName());
        this.tool = plugin.getTool();
        setPopupMenuData(new MenuData(new String[] {"Explain this function" }, null, "RevEng.AI"));
        this.callback = new TaskCallback<String>() {
			
			@Override
			public void onTaskError(Exception e) {
				// TODO Auto-generated method stub
				
			}
			
			@Override
			public void onTaskCompleted(String result) {
				// TODO Auto-generated method stub
				
			}
		};
    }

    @Override
    public boolean isEnabledForContext(ActionContext context) {
        if (!(context instanceof DecompilerActionContext)) {
            return false;
        }
        DecompilerActionContext decompilerContext = (DecompilerActionContext) context;
        
        return true;
    }

    @Override
    public void actionPerformed(ActionContext context) {
        if (!(context instanceof DecompilerActionContext)) {
            return;
        }
        
        DecompilerActionContext decompilerContext = (DecompilerActionContext) context;
        DecompInterface decompiler = new DecompInterface();
        
        Program prog = RE_AIToolkitHelper.getInstance().getFlatAPI().getCurrentProgram();
        decompiler.openProgram(prog);
        
        boolean initialized = decompiler.openProgram(prog);
        if (!initialized) {
            System.err.println("Failed to initialize DecompInterface");
            return;
        }
        
        Function func = prog.getFunctionManager().getFunctionAt(decompilerContext.getAddress());
        
        if (func == null) {
        	System.err.println("No function at given address");
        	return;
        }
        
        DecompileOptions options = decompiler.getOptions();
        if (options == null) {
            options = new DecompileOptions();
            decompiler.setOptions(options);
        }

        int timeout = options.getDefaultTimeout();
        
        DecompileResults results = decompiler.decompileFunction(func, timeout, null);
        
        if (!results.decompileCompleted()) {
        	System.err.println("Issue decompiling function");
        	return;
        }
        
        ClangTokenGroup decompiledFunction = results.getCCodeMarkup();
        
        Task task = new ExplainFunctionTask(callback, decompiledFunction.toString());
		TaskLauncher.launch(task);
    }
}
