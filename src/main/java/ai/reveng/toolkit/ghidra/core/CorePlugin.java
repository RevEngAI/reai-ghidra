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
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.recentanalyses.RecentAnalysisDialog;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.types.*;

import ai.reveng.toolkit.ghidra.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.core.services.function.export.ExportFunctionBoundariesService;
import ai.reveng.toolkit.ghidra.core.services.function.export.ExportFunctionBoundariesServiceImpl;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingService;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingServiceImpl;
import ai.reveng.toolkit.ghidra.core.types.ProgramWithBinaryID;
import ai.reveng.toolkit.ghidra.core.ui.wizard.SetupWizardManager;
import ai.reveng.toolkit.ghidra.core.ui.wizard.SetupWizardStateKey;
import docking.ActionContext;
import docking.action.builder.ActionBuilder;
import docking.widgets.OptionDialog;
import docking.wizard.WizardManager;
import docking.wizard.WizardState;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import docking.options.OptionsService;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
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
	servicesRequired = { OptionsService.class },
	servicesProvided = { GhidraRevengService.class, ExportFunctionBoundariesService.class, ReaiLoggingService.class },
	eventsConsumed = { RevEngAIAnalysisStatusChangedEvent.class}
)
//@formatter:on
public class CorePlugin extends ProgramPlugin {
	public static final String REAI_WIZARD_RUN_PREF = "REAISetupWizardRun";
	public static final String REAI_OPTIONS_CATEGORY = "RevEngAI Options";

	private GhidraRevengService revengService;
	private ExportFunctionBoundariesService exportFunctionBoundariesService;
	private ReaiLoggingService loggingService;

	private PluginTool tool;
	private ApiInfo apiInfo;

	public CorePlugin(PluginTool tool) {
		super(tool);

		this.tool = tool;

		var toolOptions =  tool;
		tool.getOptions(REAI_OPTIONS_CATEGORY).registerOption(REAI_WIZARD_RUN_PREF, "false", null, "If the setup wizard has been run");
		loggingService = new ReaiLoggingServiceImpl();
		registerServiceProvided(ReaiLoggingService.class, loggingService);



		// Try to get the API info from the local config, if it's not there, run the setup wizard
		getApiInfoFromConfig().ifPresentOrElse(
				info -> apiInfo = info,
				() -> { runSetupWizard(); apiInfo = getApiInfoFromConfig().orElseThrow();}
		);

		revengService = new GhidraRevengService(apiInfo);
		registerServiceProvided(GhidraRevengService.class, revengService);

		exportFunctionBoundariesService = new ExportFunctionBoundariesServiceImpl(tool);
		registerServiceProvided(ExportFunctionBoundariesService.class, exportFunctionBoundariesService);

		setupActions();

	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);
		if (event instanceof RevEngAIAnalysisStatusChangedEvent pickedEvent) {
			if (pickedEvent.getStatus() == AnalysisStatus.Complete) {
				Msg.info(this, "Finished analysis became available for: " + pickedEvent.getProgramWithBinaryID());
				revengService.handleAnalysisCompletion(pickedEvent);
			}
		}
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

		new ActionBuilder("Run Setup Wizard", this.toString())
				.withContext(ActionContext.class)
				.enabledWhen(c -> !hasSetupWizardRun())
				.onAction(context -> runSetupWizard())
				.menuPath(new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "Run Setup Wizard" })
				.buildAndInstall(tool);

//		new ActionBuilder("Export Plugin Logs", getName())
//				.onAction(context -> exportLogs())
//				.menuPath(new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "Export Logs" })
//				.buildAndInstall(tool);


		new ActionBuilder("Connect to existing analysis", this.toString())
				.withContext(ProgramActionContext.class)
				.enabledWhen(c -> !revengService.isKnownProgram(c.getProgram()))
				.onAction(context -> {
					RecentAnalysisDialog dialog = new RecentAnalysisDialog(tool, context.getProgram());
					tool.showDialog(dialog);
				})
				.menuPath(new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "Connect to existing analysis" })
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
			tool.firePluginEvent(
					new RevEngAIAnalysisStatusChangedEvent(
					"programActivated",
							new ProgramWithBinaryID(program, binID),
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

}
