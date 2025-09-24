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

import java.awt.*;
import java.io.File;
import java.io.FileNotFoundException;
import java.net.URI;
import java.util.Optional;

import ai.reveng.toolkit.ghidra.binarysimilarity.BinarySimilarityPlugin;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.about.AboutDialog;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.analysiscreation.RevEngAIAnalysisOptionsDialog;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.misc.AnalysisLogComponent;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.recentanalyses.RecentAnalysisDialog;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.help.HelpDialog;
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
import docking.action.DockingAction;
import docking.action.MenuData;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ghidra.util.Msg;

import javax.swing.*;

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
    private static final Logger log = LoggerFactory.getLogger(CorePlugin.class);

    // Store references to actions that need to be refreshed
    private DockingAction createNewAction;
    private DockingAction attachToExistingAction;
    private DockingAction detachAction;
    private DockingAction checkStatusAction;
    private DockingAction viewInPortalAction;

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

		new ActionBuilder("Configure", this.toString())
				.withContext(ActionContext.class)
				.onAction(context ->  {
					runSetupWizard();
				})
				.menuPath(new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "Configure" })
				.menuGroup(CorePlugin.REAI_PLUGIN_SETUP_MENU_GROUP, "100")
				.buildAndInstall(tool);

        new ActionBuilder("Help", this.toString())
                .withContext(ActionContext.class)
                .onAction(context ->  {
                    var helpDialog = new HelpDialog(tool);
                    tool.showDialog(helpDialog);
                })
                .menuPath(new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "Help" })
                .menuGroup(CorePlugin.REAI_PLUGIN_SETUP_MENU_GROUP, "200")
                .buildAndInstall(tool);

        new ActionBuilder("About", this.toString())
                .withContext(ActionContext.class)
                .onAction(context ->  {
                    var aboutDialog = new AboutDialog(tool);
                    tool.showDialog(aboutDialog);
                })
                .menuPath(new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "About" })
                .menuGroup(CorePlugin.REAI_PLUGIN_SETUP_MENU_GROUP, "300")
                .buildAndInstall(tool);

        createNewAction = new ActionBuilder("Create new", this.getName())
                .enabledWhen(context -> {
                    var currentProgram = tool.getService(ProgramManager.class).getCurrentProgram();
                    if (currentProgram == null) {
                        loggingService.info("Create new action disabled: No current program");
                        return false;
                    }
                    boolean isKnown = revengService.isKnownProgram(currentProgram);
                    boolean shouldEnable = !isKnown;
                    loggingService.info("Create new action enabled: " + shouldEnable + " (program: " + currentProgram.getName() + ", isKnown: " + isKnown + ")");
                    return shouldEnable;
                })
                .onAction(context -> {
                    var program = tool.getService(ProgramManager.class).getCurrentProgram();
                    if (!GhidraProgramUtilities.isAnalyzed(program)) {
                        Msg.showInfo(this, null, ReaiPluginPackage.WINDOW_PREFIX + "Create new",
                                "Program has not been auto-analyzed by Ghidra yet. Please run auto-analysis first.");
                        return;
                    }
                    var analysisOptionsDialog = new RevEngAIAnalysisOptionsDialog(this, program);
                    tool.showDialog(analysisOptionsDialog);
                })
                .menuPath(new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "Analysis", "Create new" })
                .menuGroup(REAI_ANALYSIS_MANAGEMENT_MENU_GROUP, "100")
                .popupMenuGroup(REAI_ANALYSIS_MANAGEMENT_MENU_GROUP)
                .popupMenuPath(new String[] { "Create new" })
                .popupMenuIcon(ReaiPluginPackage.REVENG_16)
                .buildAndInstall(tool);

		attachToExistingAction = new ActionBuilder("Attach to existing", this.toString())
				.enabledWhen(c -> {
                    var currentProgram = tool.getService(ProgramManager.class).getCurrentProgram();
                    if (currentProgram == null) {
                        loggingService.info("Attach to existing action disabled: No current program");
                        return false;
                    }
                    boolean isKnown = revengService.isKnownProgram(currentProgram);
                    boolean shouldEnable = !isKnown;
                    loggingService.info("Attach to existing action enabled: " + shouldEnable + " (program: " + currentProgram.getName() + ", isKnown: " + isKnown + ")");
                    return shouldEnable;
                })
				.onAction(context -> {
					var currentProgram = tool.getService(ProgramManager.class).getCurrentProgram();
					RecentAnalysisDialog dialog = new RecentAnalysisDialog(tool, currentProgram);
					tool.showDialog(dialog);
				})
				.menuPath(new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "Analysis", "Attach to existing" })
				.menuGroup(REAI_ANALYSIS_MANAGEMENT_MENU_GROUP, "200")
				// Also add this to the context action submenu to make it clear that this still needs to be done
				.popupMenuPath(new String[] { "Attach to existing" })
				.popupMenuGroup(REAI_ANALYSIS_MANAGEMENT_MENU_GROUP)
				.popupMenuIcon(ReaiPluginPackage.REVENG_16)
				.buildAndInstall(tool);

		detachAction = new ActionBuilder("Detach", this.toString())
				.enabledWhen(c -> {
                    var currentProgram = tool.getService(ProgramManager.class).getCurrentProgram();
                    if (currentProgram == null) {
                        loggingService.info("Detach action disabled: No current program");
                        return false;
                    }
                    boolean isKnown = revengService.isKnownProgram(currentProgram);
                    loggingService.info("Detach action enabled: " + isKnown + " (program: " + currentProgram.getName() + ", isKnown: " + isKnown + ")");
                    return isKnown;
                })
				.onAction(context -> {
					var program = tool.getService(ProgramManager.class).getCurrentProgram();
					var analysisID = this.revengService.getAnalysisIDFor(program);
					var displayText = analysisID.map(id -> "analysis " + id.id());

					var result = OptionDialog.showOptionDialogWithCancelAsDefaultButton(
							tool.getToolFrame(),
							"Detach from " + displayText,
							"Are you sure you want to remove the association with " + displayText + "?",
							"Detach",
							OptionDialog.QUESTION_MESSAGE);
					if (result == OptionDialog.YES_OPTION) {
						// For now this is the only place to trigger the removal of the association
						// If this changes, the RevEngAIAnalysisStatusChanged event should be changed to accommodate
						// this kind of event
						program.withTransaction("Undo binary association", () -> revengService.removeProgramAssociation(program));

						// Refresh action states after detaching
                        tool.contextChanged(null);
					}

				})
				.menuPath(new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "Analysis", "Detach" })
				.menuGroup(REAI_ANALYSIS_MANAGEMENT_MENU_GROUP, "300")
				.buildAndInstall(tool);

		checkStatusAction = new ActionBuilder("Check status", this.getName())
				.enabledWhen(context -> {
                    var currentProgram = tool.getService(ProgramManager.class).getCurrentProgram();
                    if (currentProgram == null) {
                        loggingService.info("Check status action disabled: No current program");
                        return false;
                    }
                    boolean isKnown = revengService.isKnownProgram(currentProgram);
                    loggingService.info("Check status action enabled: " + isKnown + " (program: " + currentProgram.getName() + ", isKnown: " + isKnown + ")");
                    return isKnown;
                })
				.onAction(context -> {
					var currentProgram = tool.getService(ProgramManager.class).getCurrentProgram();
					var binID = revengService.getBinaryIDFor(currentProgram).orElseThrow();
					var analysisID = revengService.getApi().getAnalysisIDfromBinaryID(binID);
					var logs = revengService.getAnalysisLog(analysisID);
					analysisLogComponent.setLogs(logs);
					AnalysisStatus status = revengService.pollStatus(binID);
					loggingService.info("Check Status: " + status);
					Msg.showInfo(this, null, ReaiPluginPackage.WINDOW_PREFIX + "Check status",
							"Status of " + binID + ": " + status);
				})
				.menuPath(new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "Analysis", "Check status" })
				.menuGroup(REAI_ANALYSIS_MANAGEMENT_MENU_GROUP, "400")
				.buildAndInstall(tool);

        viewInPortalAction = new ActionBuilder("View in portal", this.getName())
                .enabledWhen(context -> {
                    var currentProgram = tool.getService(ProgramManager.class).getCurrentProgram();
                    if (currentProgram == null) {
                        loggingService.info("View in portal action disabled: No current program");
                        return false;
                    }
                    boolean isKnown = revengService.isKnownProgram(currentProgram);
                    loggingService.info("View in portal action enabled: " + isKnown + " (program: " + currentProgram.getName() + ", isKnown: " + isKnown + ")");
                    return isKnown;
                })
                .onAction(context -> {
                    var currentProgram = tool.getService(ProgramManager.class).getCurrentProgram();
                    var binID = revengService.getBinaryIDFor(currentProgram).orElseThrow();
                    revengService.openPortal("analyses", String.valueOf(binID.value()));
                })
                .menuPath(new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "Analysis", "View in portal" })
                .menuGroup(REAI_ANALYSIS_MANAGEMENT_MENU_GROUP, "400")
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

	public void setLogs(String logs) {
		analysisLogComponent.setLogs(logs);
	}
}
