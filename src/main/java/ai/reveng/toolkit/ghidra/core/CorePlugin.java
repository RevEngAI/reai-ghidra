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
package ai.reveng.toolkit.ghidra.core;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.Optional;

import ai.reveng.toolkit.ghidra.binarysimilarity.BinarySimilarityPlugin;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.analysiscreation.RevEngAIAnalysisOptionsDialog;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.misc.AnalysisLogComponent;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.recentanalyses.RecentAnalysisDialog;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.ProcessingLimboApi;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.SimpleMatchesApi;
import ai.reveng.toolkit.ghidra.core.services.api.types.*;

import ai.reveng.toolkit.ghidra.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.core.services.function.export.ExportFunctionBoundariesService;
import ai.reveng.toolkit.ghidra.core.services.function.export.ExportFunctionBoundariesServiceImpl;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingService;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingToConsole;
import ai.reveng.toolkit.ghidra.core.types.ProgramWithBinaryID;
import ai.reveng.toolkit.ghidra.core.ui.wizard.SetupWizardManager;
import ai.reveng.toolkit.ghidra.core.ui.wizard.SetupWizardStateKey;
import docking.ActionContext;
import docking.action.builder.ActionBuilder;
import docking.widgets.OptionDialog;
import docking.wizard.WizardManager;
import docking.wizard.WizardState;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ConsoleService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.*;
import docking.options.OptionsService;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.Msg;

/**
 * CorePlugin for accessing the RevEng.AI Platform
 * It provides the {@link GhidraRevengService}
 * This is then used by other plugins to implement functionalities
 *
 * The UI components provided by this plugin are those for managing the basic actions such as
 * - running the setup wizard
 * - uploading a binary to the platform
 *
 * Other concepts such as creating a new analysis for a binary are still blurred between this and the
 * {@link BinarySimilarityPlugin}
 *
 * This distinction will be made clearer in future versions, when more features are available on the platform
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = ReaiPluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Toolkit for using the RevEng.AI API",
	description = "Toolkit for using RevEng.AI API",
	servicesRequired = { OptionsService.class, ConsoleService.class},
	servicesProvided = { GhidraRevengService.class, ExportFunctionBoundariesService.class, ReaiLoggingService.class },
	eventsConsumed = { RevEngAIAnalysisStatusChangedEvent.class}
)
//@formatter:on
public class CorePlugin extends ProgramPlugin {
	public static final String REAI_WIZARD_RUN_PREF = "REAISetupWizardRun";
	public static final String REAI_OPTIONS_CATEGORY = "RevEngAI Options";
	private static final String REAI_ANALYSIS_MANAGEMENT_MENU_GROUP = "RevEng.AI Analysis Management";
	private static final String REAI_PLUGIN_SETUP_MENU_GROUP = "RevEng.AI Setup";
	private static final String REAI_PLUGIN_PORTAL_MENU_GROUP = "RevEng.AI Portal";

	private GhidraRevengService revengService;
	private ExportFunctionBoundariesService exportFunctionBoundariesService;
	private ReaiLoggingService loggingService;
	private final AnalysisLogComponent analysisLogComponent;


	private PluginTool tool;
	private ApiInfo apiInfo;

	@Override
	public void serviceAdded(Class<?> interfaceClass, Object service) {
		if (interfaceClass == ConsoleService.class && loggingService instanceof ReaiLoggingToConsole) {
			ReaiLoggingToConsole reaiLoggingToConsole = (ReaiLoggingToConsole) loggingService;
			reaiLoggingToConsole.setConsoleService((ConsoleService) service);
		}
	}

	public CorePlugin(PluginTool tool) {
		super(tool);

		this.tool = tool;

		var toolOptions =  tool;
		tool.getOptions(REAI_OPTIONS_CATEGORY).registerOption(REAI_WIZARD_RUN_PREF, "false", null, "If the setup wizard has been run");
		loggingService = new ReaiLoggingToConsole(tool.getService(ConsoleService.class));
		registerServiceProvided(ReaiLoggingService.class, loggingService);



		// Try to get the API info from the local config, if it's not there, run the setup wizard
		getApiInfoFromConfig().ifPresentOrElse(
				info -> apiInfo = info,
				() -> { runSetupWizard(); apiInfo = getApiInfoFromConfig().orElseThrow();}
		);
		// Check if the System Property to use a Mock is set
		String mock;
		if ((mock = System.getProperty("reai.mock")) != null) {
			loggingService.warn("Using Mock API: " + mock);
			apiInfo = new ApiInfo("mock", "mock");
			switch (mock) {
				case "limbo":
					revengService = new GhidraRevengService(new ProcessingLimboApi());
					break;
				case "simpleMatches":
					revengService = new GhidraRevengService(new SimpleMatchesApi());
					break;
				default:
					throw new UnsupportedOperationException("Unknown mock type: " + mock);
			}
			revengService = new GhidraRevengService(new ProcessingLimboApi());
		} else {
			revengService = new GhidraRevengService(apiInfo);
		}
		registerServiceProvided(GhidraRevengService.class, revengService);

		exportFunctionBoundariesService = new ExportFunctionBoundariesServiceImpl(tool);
		registerServiceProvided(ExportFunctionBoundariesService.class, exportFunctionBoundariesService);

		// Install analysis log viewer
		analysisLogComponent = new AnalysisLogComponent(tool);
		tool.addComponentProvider(analysisLogComponent, false);

		setupActions();

		loggingService.info("CorePlugin initialized");

	}


	private Optional<ApiInfo> getApiInfoFromToolOptions(){
		var apikey = tool.getOptions(REAI_OPTIONS_CATEGORY).getString(ReaiPluginPackage.OPTION_KEY_APIKEY, "invalid");
		var hostname = tool.getOptions(REAI_OPTIONS_CATEGORY).getString(ReaiPluginPackage.OPTION_KEY_HOSTNAME, "unknown");
		if (apikey.equals("invalid") || hostname.equals("unknown")) {
			return Optional.empty();
		}
		var apiInfo = new ApiInfo(hostname, apikey);
//		apiInfo.checkValidity();
		return Optional.of(apiInfo);
	}

	/**
	 * Attempts to generate an {@link ApiInfo} object from the config file
	 * @return
	 */
	private Optional<ApiInfo> getApiInfoFromConfig(){
        try {
            return Optional.of(ApiInfo.fromConfig());
        } catch (FileNotFoundException e) {
			loggingService.error(e.getMessage());
			Msg.showError(this, null, "Load Config", "Unable to find RevEng config file");
            return Optional.empty();
        }

    }

	private void setupActions() {

		new ActionBuilder("Re-Run Setup Wizard", this.toString())
				.withContext(ActionContext.class)
				.onAction(context ->  {
					runSetupWizard();
				})
				.menuPath(new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "Run Setup Wizard" })
				.menuGroup(CorePlugin.REAI_PLUGIN_SETUP_MENU_GROUP)
				.buildAndInstall(tool);

		new ActionBuilder("Connect to existing analysis", this.toString())
				.withContext(ProgramActionContext.class)
				.enabledWhen(c -> !revengService.isKnownProgram(c.getProgram()))
				.onAction(context -> {
					RecentAnalysisDialog dialog = new RecentAnalysisDialog(tool, context.getProgram());
					tool.showDialog(dialog);
				})
				.menuPath(new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "Connect to existing analysis" })
				.menuGroup(REAI_ANALYSIS_MANAGEMENT_MENU_GROUP)
				// Also add this to the context action submenu to make it clear that this still needs to be done
				.popupMenuPath(new String[] { "Connect to existing analysis" })
				.popupMenuGroup(REAI_ANALYSIS_MANAGEMENT_MENU_GROUP)
				.popupMenuIcon(ReaiPluginPackage.REVENG_16)
				.buildAndInstall(tool);

		new ActionBuilder("Remove analysis association", this.toString())
				.withContext(ProgramActionContext.class)
				.enabledWhen(c -> revengService.isKnownProgram(c.getProgram()))
				.onAction(context -> {
					var result = OptionDialog.showOptionDialogWithCancelAsDefaultButton(
							tool.getToolFrame(),
							"Remove analysis association",
							"Are you sure you want to remove the association with the analysis?",
							"Remove",
							OptionDialog.QUESTION_MESSAGE);
					if (result == OptionDialog.YES_OPTION) {
						// For now this is the only place to trigger the removal of the association
						// If this changes, the RevEngAIAnalysisStatusChanged event should be changed to accommodate
						// this kind of event
						var program = context.getProgram();
						program.withTransaction("Undo binary association", () -> revengService.removeProgramAssociation(program));
					}

				})
				.menuPath(new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "Remove analysis association" })
				.menuGroup(REAI_ANALYSIS_MANAGEMENT_MENU_GROUP)
				.buildAndInstall(tool);

		new ActionBuilder("Check Analysis Status", this.getName())
				.withContext(ProgramActionContext.class)
				.enabledWhen(context -> context.getProgram() != null && revengService.isKnownProgram(context.getProgram()))
				.onAction(context -> {
					var binID = revengService.getBinaryIDFor(context.getProgram()).orElseThrow();
					var analysisID = revengService.getApi().getAnalysisIDfromBinaryID(binID);
					var logs = revengService.getAnalysisLog(analysisID);
					analysisLogComponent.setLogs(logs);
					AnalysisStatus status = revengService.pollStatus(binID);
					loggingService.info("Check Status: " + status);
					Msg.showInfo(this, null, ReaiPluginPackage.WINDOW_PREFIX + "Check Analysis Status",
							"Status of " + binID + ": " + status);
				})
				.menuPath(new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "Check Analysis Status" })
				.menuGroup(REAI_ANALYSIS_MANAGEMENT_MENU_GROUP)
//				.popupMenuPath(new String[] { "Check Analysis Status" })
				.buildAndInstall(tool);

		new ActionBuilder("Push Function names to portal", this.toString())
				.withContext(ProgramActionContext.class)
				.onAction(context -> {
					var renameMap = revengService.pushUserFunctionNamesToBackend(context.getProgram());
					if (renameMap.isEmpty()){
						Msg.showInfo(this, null, "Push Function names to portal", "No functions were renamed");
					} else {
						Msg.showInfo(this, null, "Push Function names to portal", "Renamed functions: " + renameMap);
					}
				})
				.menuPath(new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "Push Function names to portal" })
				.menuGroup(REAI_PLUGIN_PORTAL_MENU_GROUP)
				.buildAndInstall(tool);

		new ActionBuilder("Open Function in RevEng.AI Portal", this.getName())
				.withContext(ProgramLocationActionContext.class)
				.enabledWhen(context -> getFunctionFromContext(context).flatMap(revengService::getFunctionIDFor).isPresent())
				.onAction(context -> {
					FunctionID fid = getFunctionFromContext(context).flatMap(revengService::getFunctionIDFor).orElseThrow();
					revengService.openFunctionInPortal(fid);

				})
				.menuPath(new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "Open Function in RevEng.AI Portal" })
				.menuGroup(REAI_PLUGIN_PORTAL_MENU_GROUP)
				.popupMenuIcon(ReaiPluginPackage.REVENG_16)
				.popupMenuGroup(REAI_PLUGIN_PORTAL_MENU_GROUP)
				.popupMenuPath(new String[] { "Open Function in RevEng.AI Portal" })
				.buildAndInstall(tool);

		new ActionBuilder("Create new RevEng.AI Analysis for Binary", this.getName())
				.enabledWhen(context -> {
					var currentProgram = tool.getService(ProgramManager.class).getCurrentProgram();
					if (currentProgram == null) {
						return false;
					}
					return !revengService.isKnownProgram(currentProgram);
				})
				.onAction(context -> {
					var program = tool.getService(ProgramManager.class).getCurrentProgram();
					if (!GhidraProgramUtilities.isAnalyzed(program)) {
						Msg.showInfo(this, null, ReaiPluginPackage.WINDOW_PREFIX + "Create new Analysis for Binary",
								"Program has not been auto-analyzed by Ghidra yet. Please run auto-analysis first.");
						return;
					}
					var analysisOptionsDialog = new RevEngAIAnalysisOptionsDialog(this, program);
					tool.showDialog(analysisOptionsDialog);
				})
				.menuPath(new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "Create new Analysis for Binary" })
				.menuGroup(REAI_ANALYSIS_MANAGEMENT_MENU_GROUP)
				.popupMenuGroup(REAI_ANALYSIS_MANAGEMENT_MENU_GROUP)
				.popupMenuPath(new String[] { "Create new Analysis for Binary" })
				.popupMenuIcon(ReaiPluginPackage.REVENG_16)
				.buildAndInstall(tool);

	}

	@Override
	protected void programActivated(Program program) {
		super.programActivated(program);

		if (!revengService.isKnownProgram(program)){
			var maybeBinID = revengService.getBinaryIDFor(program);
			if (maybeBinID.isEmpty()){
				Msg.info(this, "Program has no saved binary ID");
				return;
			}
			var binID = maybeBinID.get();
			AnalysisStatus status = revengService.pollStatus(binID);
			var analysisID = revengService.getApi().getAnalysisIDfromBinaryID(binID);
			tool.firePluginEvent(
					new RevEngAIAnalysisStatusChangedEvent(
					"programActivated",
							new ProgramWithBinaryID(program, binID, analysisID),
							status));
		}
	}

	@Override
	public void init() {
		super.init();

	}

	private boolean hasSetupWizardRun() {
		String value = tool.getOptions(REAI_OPTIONS_CATEGORY).getString(REAI_WIZARD_RUN_PREF, "false");
		return Boolean.parseBoolean(value);
	}

	private void setWizardRun() {
		tool.getOptions(REAI_OPTIONS_CATEGORY).setString(REAI_WIZARD_RUN_PREF, "true");
	}

	private void runSetupWizard() {
		loggingService.info("First time running setup wizard");
		SetupWizardManager setupManager = new SetupWizardManager(new WizardState<SetupWizardStateKey>(), getTool(),
				loggingService);
		WizardManager wizardManager = new WizardManager("RevEng.ai Setup Wizard", true, setupManager);
		wizardManager.showWizard(tool.getToolFrame());

		return;
	}


	private void exportLogs(){
		GhidraFileChooser fileChooser = new GhidraFileChooser(null);
		fileChooser.setFileSelectionMode(GhidraFileChooserMode.DIRECTORIES_ONLY);

		File outDir = fileChooser.getSelectedFile(true);
		fileChooser.dispose();

		if (outDir == null) {
			loggingService.error("No dir selected for logfile export");
			Msg.showError(outDir, null, ReaiPluginPackage.WINDOW_PREFIX + "Export logfile",
					"No output directory provided to export logs to", null);
			return;
		}

		loggingService.export(outDir.toString(), "reai_logs");

		Msg.showInfo(outDir, null, ReaiPluginPackage.WINDOW_PREFIX + "Export Logs",
				"Successfully exported logs to: " + outDir.toString());
	}

	private Optional<Function> getFunctionFromContext(ProgramLocationActionContext context) {
		return Optional.ofNullable(context.getProgram().getFunctionManager().getFunctionContaining(context.getAddress()));
	}

	public void setLogs(String logs) {
		analysisLogComponent.setLogs(logs);
	}
}
