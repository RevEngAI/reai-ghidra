/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ai.reveng.toolkit.ghidra.binarysimularity;

import ai.reveng.toolkit.ghidra.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.binarysimularity.ui.aidecompiler.AIDecompiledWindow;
import ai.reveng.toolkit.ghidra.binarysimularity.ui.autoanalysis.AutoAnalysisDockableDialog;
import ai.reveng.toolkit.ghidra.binarysimularity.ui.functionsimularity.FunctionSimularityDockableDialog;
import ai.reveng.toolkit.ghidra.core.RevEngAIAnalysisStatusChanged;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.ModelName;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisStatus;
import ai.reveng.toolkit.ghidra.core.services.api.types.BinaryHash;
import ai.reveng.toolkit.ghidra.core.services.api.types.BinaryID;
import ai.reveng.toolkit.ghidra.core.services.api.types.ProgramWithBinaryID;
import ai.reveng.toolkit.ghidra.core.services.function.export.ExportFunctionBoundariesService;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingService;
import docking.action.builder.ActionBuilder;
import docking.widgets.OptionDialog;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.Msg;
import ghidra.util.task.MonitoredRunnable;
import ghidra.util.task.RunManager;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;

import static ai.reveng.toolkit.ghidra.ReaiPluginPackage.INVALID_BINARY_ID;

/**
 * This plugin provides features for performing binary code similarity using the
 * RevEng.AI API
 *
 * This depend on an Analysis ID being associated with a program
 *
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = ReaiPluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Support for Binary Similarity Featrues of RevEng.AI Toolkit.",
	description = "Enable features that support binary similarity operations, including binary upload, and auto-renaming",
	servicesRequired = { GhidraRevengService.class, ProgramManager.class, ExportFunctionBoundariesService.class, ReaiLoggingService.class }
)
//@formatter:on
public class BinarySimularityPlugin extends ProgramPlugin {
	private final AutoAnalysisDockableDialog autoAnalyse;
	private final AIDecompiledWindow decompiledWindow;
	private GhidraRevengService apiService;
	public ReaiLoggingService loggingService;
	private RunManager runMgr;

	public final static String REVENG_AI_NAMESPACE = "RevEng.AI";

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public BinarySimularityPlugin(PluginTool tool) {
		super(tool);
		runMgr = new RunManager();

		loggingService = tool.getService(ReaiLoggingService.class);
		if (loggingService == null) {
			Msg.error(this, "Unable to access logging service");
		}

		autoAnalyse = new AutoAnalysisDockableDialog(tool);
		tool.addComponentProvider(autoAnalyse, false);

		setupActions();

		// Setup windows

		decompiledWindow = new AIDecompiledWindow(tool, REVENG_AI_NAMESPACE);
		decompiledWindow.addToTool();

	}

	@Override
	public void serviceAdded(Class<?> interfaceClass, Object service) {
		if (interfaceClass == ReaiLoggingService.class) {
			loggingService = (ReaiLoggingService) service;
		}
	}

	private void setupActions() {

//		uploadBinary.setMenuBarData(new MenuData(new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "Upload Binary" },
//				ReaiPluginPackage.NAME));
//		uploadBinary.setPopupMenuData(new MenuData(new String[] { "Upload Binary" }, ReaiPluginPackage.NAME));
//		tool.addAction(uploadBinary);

		new ActionBuilder("Upload Binary", this.getName())
				.withContext(ProgramActionContext.class)
				.enabledWhen(context -> context.getProgram() != null)
				.onAction(context -> {
					TaskLauncher.launchModal("Upload Binary", monitor -> {
						monitor.setMessage("Uploading binary...");
						BinaryHash hash = apiService.upload(context.getProgram());
						Msg.showInfo(this, null, ReaiPluginPackage.WINDOW_PREFIX + "Upload Binary",
								"Binary uploaded with hash: " + hash.sha256());
					});
				})
				.menuPath(new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "Upload Binary" })
//				.popupMenuPath(new String[] { "Upload Binary" })
				.buildAndInstall(tool);

		new ActionBuilder("Create new RevEng.AI Analysis for Binary", this.getName())
				.withContext(ProgramActionContext.class)
				.enabledWhen(context -> context.getProgram() != null && !apiService.isKnownProgram(context.getProgram()))
				.onAction(context -> {
					TaskLauncher.launchModal("Create new Analysis for Binary", monitor -> {
						// Check if the program has been analyzed already
//						isAnalyzed = options.getBoolean(Program.ANALYZED_OPTION_NAME, false);
						if (!GhidraProgramUtilities.isAnalyzed(context.getProgram())) {
							Msg.showInfo(this, null, ReaiPluginPackage.WINDOW_PREFIX + "Create new Analysis for Binary",
									"Program has not been auto-analyzed by Ghidra yet. Please run auto-analysis first.");
							return;
						}
						// Get the available models
						monitor.setMessage("Getting available models...");
						var models = apiService.getAvailableModels();
						var suggestedModel = apiService.getModelNameForProgram(context.getProgram(), models);
						// Show user a dropdown menu to pick the model
						var selectedModel = OptionDialog.showInputChoiceDialog(
								null,
								ReaiPluginPackage.WINDOW_PREFIX + "Create new Analysis for Binary",
								"Select a model to use for analysis",
								models.stream().map(ModelName::modelName).toArray(String[]::new),
								suggestedModel.modelName(),
								OptionDialog.QUESTION_MESSAGE);

						if (selectedModel == null) {
							// User canceled the model choice dialog, so we cancel the analysis task
							return;
						}
						monitor.setMessage("Uploading binary...");
						apiService.upload(context.getProgram());
						monitor.setProgress(99);
						monitor.setMessage("Launching Analysis");
						ProgramWithBinaryID binID = apiService.analyse(context.getProgram(), new ModelName(selectedModel));
						Msg.showInfo(this, null, ReaiPluginPackage.WINDOW_PREFIX + "Create new Analysis for Binary",
								"Analysis is running for: " + binID + "\n"
										+ "You will be notified when the analysis is complete.");
//						apiService.addBinaryIDtoProgramOptions(context.getProgram(), binID);
						spawnAnalysisStatusChecker(binID);
						// Trigger a context refresh so the UI status of the actions gets updated
						// because now other actions are available
						tool.contextChanged(null);
					});

				})
				.menuPath(new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "Create new Analysis for Binary" })
				.buildAndInstall(tool);


		new ActionBuilder("Check Analysis Status", this.getName())
				.withContext(ProgramActionContext.class)
				.enabledWhen(context -> context.getProgram() != null && apiService.isKnownProgram(context.getProgram()))
				.onAction(context -> {
					var binID = apiService.getBinaryIDFor(context.getProgram()).orElseThrow();
					AnalysisStatus status = apiService.status(binID);
					loggingService.info("Check Status: " + status);
					Msg.showInfo(this, null, ReaiPluginPackage.WINDOW_PREFIX + "Check Analysis Status",
							"Status of " + binID + ": " + status);
				})
				.menuPath(new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "Check Analysis Status" })
//				.popupMenuPath(new String[] { "Check Analysis Status" })
				.buildAndInstall(tool);

		new ActionBuilder("Rename From Similar Functions", this.getName())
				.withContext(ProgramLocationActionContext.class)
				.enabledWhen(context -> {
					var func = context.getProgram().getFunctionManager().getFunctionContaining(context.getAddress());
					return func != null
							&& apiService.isKnownProgram(context.getProgram())
							&& apiService.isProgramAnalysed(context.getProgram());
				})
				.onAction(context -> {
					var func = context.getProgram().getFunctionManager().getFunctionContaining(context.getAddress());
					if (!apiService.isKnownFunction(func)){
						Msg.showError(this, null, ReaiPluginPackage.WINDOW_PREFIX + "Rename From Similar Functions",
								"Function is not known to the RevEng.AI API." +
										"This can happen if the function boundaries do not match.\n" +
								"You can create a new analysis based on the current analysis state to fix this.");
						return;
					}

					FunctionSimularityDockableDialog renameDialogue = new FunctionSimularityDockableDialog(func, tool);
					tool.showDialog(renameDialogue);
				})
//				.keyBinding(KeyEvent.VK_R, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK))
				.popupMenuPath(new String[] { "Rename From Similar Functions" })
				.popupMenuGroup(ReaiPluginPackage.NAME)
				.buildAndInstall(tool);


		new ActionBuilder("Auto Analysis Similar Functions", this.getName())
				.menuGroup(ReaiPluginPackage.NAME)
				.menuPath(ReaiPluginPackage.MENU_GROUP_NAME, "Auto Analyse Binary Symbols")
				.withContext(ProgramActionContext.class)
				.enabledWhen(context -> apiService.isKnownProgram(context.getProgram()))
				.onAction(context -> {
					if (apiService.status(context.getProgram()) != AnalysisStatus.Complete) {
						Msg.showError(this, null, ReaiPluginPackage.WINDOW_PREFIX + "Auto Analyse Binary Symbols",
								"Analysis must have completed before running name import");
						return;
					}
					tool.showComponentProvider(autoAnalyse, true);
				})
//				.keyBinding()autoAnalysisAction.setKeyBindingData( new KeyBindingData(KeyEvent.VK_A, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK));
				.buildAndInstall(tool);

		new ActionBuilder("Decompile via RevEng.AI", this.getName())
				.withContext(ProgramLocationActionContext.class)
				.enabledWhen(context -> {
					var func = context.getProgram().getFunctionManager().getFunctionContaining(context.getAddress());
					return func != null
							&& apiService.isKnownProgram(context.getProgram())
							&& apiService.isProgramAnalysed(context.getProgram());
				})
				.onAction(context -> {
					var func = context.getProgram().getFunctionManager().getFunctionContaining(context.getAddress());
					if (!apiService.isKnownFunction(func)) {
						Msg.showError(this, null, ReaiPluginPackage.WINDOW_PREFIX + "Decompile via RevEng.AI",
								"Function is not known to the RevEng.AI API." +
										"This can happen if the function boundaries do not match.\n" +
										"You can create a new analysis based on the current analysis state to fix this.");
						return;
					}
					// Spawn Task to decompile the function
					TaskLauncher.launchModal("Decompile via RevEng.AI", monitor -> {
						monitor.setMessage("Decompiling function...");
						var result = apiService.decompileFunctionViaAI(func, monitor, decompiledWindow);
					});
				})
				.popupMenuPath(new String[] { "Decompile via RevEng.AI" })
				.popupMenuGroup(ReaiPluginPackage.NAME)
				.buildAndInstall(tool);

	}

	@Override
	public void init() {
		super.init();

		apiService = tool.getService(GhidraRevengService.class);
	}

	private void spawnAnalysisStatusChecker(ProgramWithBinaryID programWithBinaryID){
		runMgr.runNext(monitor -> {
            monitor.setMessage("Checking analysis status");
			var binID = programWithBinaryID.binaryID();
            // Check the status of the analysis every 5 seconds
            AnalysisStatus lastStatus = null;
            while (true) {
                AnalysisStatus currentStatus = apiService.status(programWithBinaryID.binaryID());
                if (currentStatus != lastStatus) {
                    tool.firePluginEvent(new RevEngAIAnalysisStatusChanged("Checker", programWithBinaryID, currentStatus));
                    lastStatus = currentStatus;
                }

				if (lastStatus == AnalysisStatus.Complete || lastStatus == AnalysisStatus.Error) {
					// Show the UI message for the completion
					Msg.showInfo(this, null, ReaiPluginPackage.WINDOW_PREFIX + "Analysis Complete",
							"Analysis for " + binID + " is complete with status: " + lastStatus);
					break;
				}

                try {
                    Thread.sleep(5000);
                } catch (InterruptedException e) {
                    loggingService.error(e.getMessage());
                }
            }
        }, "Checking analysis status", 0);
	}

}
