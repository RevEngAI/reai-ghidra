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
package ai.reveng.toolkit.ghidra.binarysimilarity;

import ai.reveng.toolkit.ghidra.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.aidecompiler.AIDecompiledWindow;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.autoanalysis.AutoAnalysisDockableDialog;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.functionsimilarity.FunctionSimilarityAction;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.functionsimilarity.FunctionSimilarityComponent;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.misc.AnalysisLogComponent;
import ai.reveng.toolkit.ghidra.core.RevEngAIAnalysisStatusChangedEvent;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.ModelName;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisStatus;
import ai.reveng.toolkit.ghidra.core.services.api.types.BinaryHash;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionID;
import ai.reveng.toolkit.ghidra.core.types.ProgramWithBinaryID;
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
import ghidra.program.model.listing.Function;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.RunManager;
import ghidra.util.task.TaskLauncher;

import java.awt.*;
import java.io.IOException;
import java.net.URI;
import java.util.Optional;

/**
 * This plugin provides features for performing binary code similarity using the
 * RevEng.AI API
 *
 * This depend on an Analysis ID being associated with a program
 *
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = ReaiPluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Support for Binary Similarity Featrues of RevEng.AI Toolkit.",
	description = "Enable features that support binary similarity operations, including binary upload, and auto-renaming",
	servicesRequired = { GhidraRevengService.class, ProgramManager.class, ExportFunctionBoundariesService.class, ReaiLoggingService.class }
)
//@formatter:on
public class BinarySimilarityPlugin extends ProgramPlugin {
	private final AutoAnalysisDockableDialog autoAnalyse;
	private final AIDecompiledWindow decompiledWindow;
	private final AnalysisLogComponent analysisLogComponent;

	public FunctionSimilarityComponent getFunctionSimilarityComponent() {
		return functionSimilarityComponent;
	}

	protected final FunctionSimilarityComponent functionSimilarityComponent;
	private GhidraRevengService apiService;
	public ReaiLoggingService loggingService;
	private RunManager runMgr;

	public final static String REVENG_AI_NAMESPACE = "RevEng.AI";

	@Override
	protected void locationChanged(ProgramLocation loc) {
		super.locationChanged(loc);
		functionSimilarityComponent.locationChanged(loc);
	}

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public BinarySimilarityPlugin(PluginTool tool) {
		super(tool);
		runMgr = new RunManager();

		loggingService = tool.getService(ReaiLoggingService.class);
		if (loggingService == null) {
			Msg.error(this, "Unable to access logging service");
		}

		autoAnalyse = new AutoAnalysisDockableDialog(tool);

		setupActions();

		// Setup windows

		decompiledWindow = new AIDecompiledWindow(tool, REVENG_AI_NAMESPACE);
		decompiledWindow.addToTool();

		functionSimilarityComponent = new FunctionSimilarityComponent(tool);
		functionSimilarityComponent.addToTool();


		// Install analysis log viewer
		analysisLogComponent = new AnalysisLogComponent(tool);
		tool.addComponentProvider(analysisLogComponent, false);

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
						apiService.addBinaryIDtoProgramOptions(context.getProgram(), binID.binaryID());
						loggingService.info("Analysis started for " + binID);
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
					var analysisID = apiService.getApi().getAnalysisIDfromBinaryID(binID);
					var logs = apiService.getAnalysisLog(analysisID);
					analysisLogComponent.setLogs(logs);
					AnalysisStatus status = apiService.pollStatus(binID);
					loggingService.info("Check Status: " + status);
					Msg.showInfo(this, null, ReaiPluginPackage.WINDOW_PREFIX + "Check Analysis Status",
							"Status of " + binID + ": " + status);
				})
				.menuPath(new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "Check Analysis Status" })
//				.popupMenuPath(new String[] { "Check Analysis Status" })
				.buildAndInstall(tool);

		tool.addAction(new FunctionSimilarityAction(this));


		new ActionBuilder("Auto Analysis Similar Functions", this.getName())
				.menuGroup(ReaiPluginPackage.NAME)
				.menuPath(ReaiPluginPackage.MENU_GROUP_NAME, "Auto Analyse Binary Symbols")
//				.withContext(ProgramActionContext.class)
//				.enabledWhen(context -> apiService.isKnownProgram(context.getProgram()))
				.enabledWhen(context -> {
					var program = tool.getService(ProgramManager.class).getCurrentProgram();
					if (program != null) {
						return apiService.isKnownProgram(program);
					} else {
						return false;
					}
				}
				)

				.onAction(context -> {
					var program = tool.getService(ProgramManager.class).getCurrentProgram();
					if (!apiService.isProgramAnalysed(program)) {
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
					TaskLauncher.launchNonModal("Decompile via RevEng.AI", monitor -> {
						monitor.setMessage("Decompiling function...");
						loggingService.info("Requested AI Decompilation for function" + func.getName());
						var result = apiService.decompileFunctionViaAI(func, monitor, decompiledWindow);
					});
				})
				.popupMenuPath(new String[] { "Decompile via RevEng.AI" })
				.popupMenuGroup(ReaiPluginPackage.NAME)
				.buildAndInstall(tool);

		new ActionBuilder("Open Function in RevEng.AI Portal", this.getName())
				.withContext(ProgramLocationActionContext.class)
				.enabledWhen(context -> getFunctionFromContext(context).flatMap(apiService::getFunctionIDFor).isPresent())
				.onAction(context -> {
                    FunctionID fid = getFunctionFromContext(context).flatMap(apiService::getFunctionIDFor).orElseThrow();
					openURI(URI.create("https://portal.reveng.ai/function/" + fid.value()));

				})
				.menuPath(new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "Open Function in RevEng.AI Portal" })
				.buildAndInstall(tool);

	}


	private boolean functionHasAssociatedID(Function function){
		return apiService.getFunctionIDFor(function).isPresent();
	}

	private Optional<Function> getFunctionFromContext(ProgramLocationActionContext context){
		return Optional.ofNullable(context.getProgram().getFunctionManager().getFunctionContaining(context.getAddress()));
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
			var analysisID = apiService.getApi().getAnalysisIDfromBinaryID(binID);
            // Check the status of the analysis every 500ms
			// TODO: In the future this can be made smarter and e.g. wait longer if the analysis log hasn't changed
            AnalysisStatus lastStatus = null;
            while (true) {
                AnalysisStatus currentStatus = apiService.pollStatus(programWithBinaryID.binaryID());
				if (currentStatus != AnalysisStatus.Queued) {
					// Analysis log endpoint only starts to return data after the analysis is processing
					String logs = apiService.getAnalysisLog(analysisID);
					analysisLogComponent.setLogs(logs);
				}
				loggingService.info("Analysis status: " + currentStatus);
                if (currentStatus != lastStatus) {
					loggingService.info("Sending RevEngAIAnalysisStatusChangedEvent for new status: " + currentStatus);
                    tool.firePluginEvent(new RevEngAIAnalysisStatusChangedEvent("Checker", programWithBinaryID, currentStatus));
                    lastStatus = currentStatus;
                }

				if (lastStatus == AnalysisStatus.Complete || lastStatus == AnalysisStatus.Error) {
					// Show the UI message for the completion
					Msg.showInfo(this, null, ReaiPluginPackage.WINDOW_PREFIX + "Analysis Complete",
							"Analysis for " + binID + " is complete with status: " + lastStatus);
					// Open the auto analysis panel
					autoAnalyse.triggerActivation();
					break;
				}

                try {
                    Thread.sleep(500);
                } catch (InterruptedException e) {
                    loggingService.error(e.getMessage());
                }
            }
        }, "Checking analysis status", 0);
	}

	private void openURI(URI uri){
		if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)
		) {
			try {
				Desktop.getDesktop().browse(uri);
			} catch (IOException e) {
				Msg.showError(
						this,
						null,
						"URI Opening Failed",
						"Browsing to URI %s failed".formatted(uri),
						e
				);
			}
		} else {
			Msg.showError(
					this,
					null,
					"URI Opening unsupported",
					"URI %s couldn't be opened because the environment doesn't support opening URLs".formatted(uri)
			);

		}
	}

}
