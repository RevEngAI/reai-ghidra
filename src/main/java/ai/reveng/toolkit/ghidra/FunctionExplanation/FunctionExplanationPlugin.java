package ai.reveng.toolkit.ghidra.FunctionExplanation;

/**
 * This plugin provides features for generating function comments summarising what the function is doing, and what its role in the wider program might be
 */
//@formatter:off

import ai.reveng.toolkit.ghidra.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.FunctionExplanation.actions.AskForFunctionExplanationAction;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingService;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;

@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = ReaiPluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Provide Function Explanation using AI",
	description = "Provides support for annotating functions in the decompiler view with human read comments on what the function does",
	servicesRequired = { TypedApiInterface.class, ProgramManager.class, ReaiLoggingService.class }
)
//@formatter:on
public class FunctionExplanationPlugin extends ProgramPlugin {
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
	}
}