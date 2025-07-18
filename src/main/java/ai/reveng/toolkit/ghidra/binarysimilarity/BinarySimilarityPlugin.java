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
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.collectiondialog.DataSetControlPanelComponent;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.functionsimilarity.FunctionSimilarityAction;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.functionsimilarity.FunctionSimilarityComponent;
import ai.reveng.toolkit.ghidra.core.RevEngAIAnalysisStatusChangedEvent;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.types.*;
import ai.reveng.toolkit.ghidra.core.services.function.export.ExportFunctionBoundariesService;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingService;
import docking.action.builder.ActionBuilder;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.TaskLauncher;

import java.util.Arrays;

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
	servicesRequired = { GhidraRevengService.class, ProgramManager.class, ExportFunctionBoundariesService.class, ReaiLoggingService.class },
	eventsConsumed = { RevEngAIAnalysisStatusChangedEvent.class, }
)
//@formatter:on
public class BinarySimilarityPlugin extends ProgramPlugin {
	private final AutoAnalysisDockableDialog autoAnalyse;
	private final AIDecompiledWindow decompiledWindow;
	private final DataSetControlPanelComponent collectionsComponent;

	public FunctionSimilarityComponent getFunctionSimilarityComponent() {
		return functionSimilarityComponent;
	}

	protected final FunctionSimilarityComponent functionSimilarityComponent;
	private GhidraRevengService apiService;
	public ReaiLoggingService loggingService;

	public final static String REVENG_AI_NAMESPACE = "RevEng.AI";


	@Override
	protected void locationChanged(ProgramLocation loc) {
		super.locationChanged(loc);
		functionSimilarityComponent.locationChanged(loc);
		decompiledWindow.locationChanged(loc);
	}

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public BinarySimilarityPlugin(PluginTool tool) {
		super(tool);

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


		// Install Collections Control Panel
		collectionsComponent = new DataSetControlPanelComponent(tool, REVENG_AI_NAMESPACE);
		collectionsComponent.addToTool();
//		tool.addComponentProvider(collectionsComponent, false);

	}

	@Override
	public void serviceAdded(Class<?> interfaceClass, Object service) {
		if (interfaceClass == ReaiLoggingService.class) {
			loggingService = (ReaiLoggingService) service;
		}
	}

	private void setupActions() {


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
						loggingService.info("Requested AI Decompilation for function " + func.getName());
						var result = apiService.decompileFunctionViaAI(func, monitor, decompiledWindow);
					});
				})
				.popupMenuPath(new String[] { "Decompile via RevEng.AI" })
				.popupMenuIcon(ReaiPluginPackage.REVENG_16)
				.popupMenuGroup(ReaiPluginPackage.MENU_GROUP_NAME)
				.buildAndInstall(tool);



	}

	@Override
	public void readDataState(SaveState saveState) {
		int[] rawCollectionIDs = saveState.getInts("collectionIDs", new int[0]);
		var restoredCollections = Arrays.stream(rawCollectionIDs)
				.mapToObj(CollectionID::new)
				.map(cID -> apiService.getApi().getCollectionInfo(cID))
				.toList();
		apiService.setActiveCollections(restoredCollections);

//		int[] rawAnalysisIDs = saveState.getInts("analysisIDs", new int[0]);
//		var restoredAnalysisIDs = Arrays.stream(rawAnalysisIDs)
//				.mapToObj(AnalysisID::new)
//				.map(aID -> apiService.getApi().getInfoForAnalysis(aID))
//				.toList();
//		apiService.setAnalysisIDMatchFilter(restoredAnalysisIDs);
//
//		collectionsComponent.reloadFromService();


	}

	@Override
	public void writeDataState(SaveState saveState) {
		int[] collectionIDs = apiService.getActiveCollections().stream().map(Collection::collectionID).mapToInt(CollectionID::id).toArray();
		saveState.putInts("collectionIDs", collectionIDs);

//		int[] analysisIDs = apiService.getActiveAnalysisIDsFilter().stream().map(AnalysisResult::analysisID).mapToInt(AnalysisID::id).toArray();
//		saveState.putInts("analysisIDs", analysisIDs);
	}


	@Override
	public void init() {
		super.init();

		apiService = tool.getService(GhidraRevengService.class);
	}

	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof RevEngAIAnalysisStatusChangedEvent analysisStatusChangedEvent) {
			if (analysisStatusChangedEvent.getStatus() == AnalysisStatus.Complete){
				autoAnalyse.triggerActivation();
			}
		}
		if (event instanceof ProgramLocationPluginEvent programLocationPluginEvent) {
			locationChanged(programLocationPluginEvent.getLocation());
		}
	}
}
