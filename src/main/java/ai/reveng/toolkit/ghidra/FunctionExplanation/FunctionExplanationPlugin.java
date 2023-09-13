package ai.reveng.toolkit.ghidra.FunctionExplanation;

/**
 * TODO: Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.io.File;

import ai.reveng.toolkit.ghidra.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.FunctionExplanation.actions.AskForFunctionExplanationAction;
import ai.reveng.toolkit.ghidra.binarysimularity.actions.RenameFromSimilarFunctionsAction;
import ai.reveng.toolkit.ghidra.binarysimularity.ui.autoanalysis.AutoAnalysisDockableDialog;
import ai.reveng.toolkit.ghidra.core.services.api.AnalysisOptions;
import ai.reveng.toolkit.ghidra.core.services.api.ApiResponse;
import ai.reveng.toolkit.ghidra.core.services.api.ApiService;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;

@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = ReaiPluginPackage.NAME,
	category = PluginCategoryNames.DECOMPILER,
	shortDescription = "Provide Function Explanation using AI",
	description = "Provides support for annotating functions in the decompiler view with human read comments on what the function does",
	servicesRequired = { ApiService.class, ProgramManager.class }
)
//@formatter:on
public class FunctionExplanationPlugin extends ProgramPlugin {
	private ApiService apiService;

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public FunctionExplanationPlugin(PluginTool tool) {
		super(tool);

		setupActions();
	}

	private void setupActions() {
		AskForFunctionExplanationAction feAction = new AskForFunctionExplanationAction(tool);
		tool.addAction(feAction);
	}

	@Override
	public void init() {
		super.init();

		// TODO: Acquire services if necessary
		apiService = tool.getService(ApiService.class);
	}
}