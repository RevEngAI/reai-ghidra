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
import java.util.Objects;
import java.util.Optional;

import ai.reveng.toolkit.ghidra.binarysimilarity.BinarySimilarityPlugin;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.analysiscreation.RevEngAIAnalysisOptionsDialog;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.misc.AnalysisLogComponent;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.recentanalyses.RecentAnalysisDialog;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.types.*;

import ai.reveng.toolkit.ghidra.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.core.services.function.export.ExportFunctionBoundariesService;
import ai.reveng.toolkit.ghidra.core.services.function.export.ExportFunctionBoundariesServiceImpl;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingService;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingToConsole;
import ai.reveng.toolkit.ghidra.core.tasks.StartAnalysisTask;
import ai.reveng.toolkit.ghidra.core.types.ProgramWithBinaryID;
import docking.action.builder.ActionBuilder;
import docking.widgets.OptionDialog;
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
import ghidra.util.task.Task;
import ghidra.util.task.TaskBuilder;
import ghidra.util.task.TaskListener;

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
	servicesRequired = { OptionsService.class, ConsoleService.class, GhidraRevengService.class},
	servicesProvided = { ExportFunctionBoundariesService.class, ReaiLoggingService.class },
    eventsConsumed = { RevEngAIAnalysisStatusChangedEvent.class}
)
//@formatter:on
public class CorePlugin extends ProgramPlugin {
	public static final String REAI_WIZARD_RUN_PREF = "REAISetupWizardRun";
	public static final String REAI_OPTIONS_CATEGORY = "RevEngAI Options";
	private static final String REAI_ANALYSIS_MANAGEMENT_MENU_GROUP = "RevEng.AI Analysis Management";
	private static final String REAI_PLUGIN_PORTAL_MENU_GROUP = "RevEng.AI Portal";

	private ExportFunctionBoundariesService exportFunctionBoundariesService;
	private ReaiLoggingService loggingService;
	private final AnalysisLogComponent analysisLogComponent;

	@Override
	public void serviceAdded(Class<?> interfaceClass, Object service) {
		if (interfaceClass == ConsoleService.class && loggingService instanceof ReaiLoggingToConsole) {
			ReaiLoggingToConsole reaiLoggingToConsole = (ReaiLoggingToConsole) loggingService;
			reaiLoggingToConsole.setConsoleService((ConsoleService) service);
		}
	}

    public GhidraRevengService getRevengService() {
        return tool.getService(GhidraRevengService.class);
    }

	public CorePlugin(PluginTool tool) {
		super(tool);


		var toolOptions =  tool;
		tool.getOptions(REAI_OPTIONS_CATEGORY).registerOption(REAI_WIZARD_RUN_PREF, "false", null, "If the setup wizard has been run");
		loggingService = new ReaiLoggingToConsole(tool.getService(ConsoleService.class));
		registerServiceProvided(ReaiLoggingService.class, loggingService);

		exportFunctionBoundariesService = new ExportFunctionBoundariesServiceImpl(tool);
		registerServiceProvided(ExportFunctionBoundariesService.class, exportFunctionBoundariesService);

		// Install analysis log viewer
		analysisLogComponent = new AnalysisLogComponent(tool);
		tool.addComponentProvider(analysisLogComponent, false);

		setupActions();

		loggingService.info("CorePlugin initialized");

	}

	private void setupActions() {


		new ActionBuilder("Connect to existing analysis", this.toString())
				.withContext(ProgramActionContext.class)
				.enabledWhen(c -> !getRevengService().isKnownProgram(c.getProgram()))
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
				.enabledWhen(c -> getRevengService().isKnownProgram(c.getProgram()))
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
						program.withTransaction("Undo binary association", () -> getRevengService().removeProgramAssociation(program));
					}

				})
				.menuPath(new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "Remove analysis association" })
				.menuGroup(REAI_ANALYSIS_MANAGEMENT_MENU_GROUP)
				.buildAndInstall(tool);

		new ActionBuilder("Check Analysis Status", this.getName())
				.withContext(ProgramActionContext.class)
				.enabledWhen(context -> context.getProgram() != null && getRevengService().isKnownProgram(context.getProgram()))
				.onAction(context -> {
                    var revengService = getRevengService();
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
					var renameMap = getRevengService().pushUserFunctionNamesToBackend(context.getProgram());
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
				.enabledWhen(context -> getFunctionFromContext(context).flatMap(getRevengService()::getFunctionIDFor).isPresent())
				.onAction(context -> {
					FunctionID fid = getFunctionFromContext(context).flatMap(getRevengService()::getFunctionIDFor).orElseThrow();
                    getRevengService().openFunctionInPortal(fid);

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
					return !getRevengService().isKnownProgram(currentProgram);
				})
				.onAction(context -> {
					var program = tool.getService(ProgramManager.class).getCurrentProgram();
					if (!GhidraProgramUtilities.isAnalyzed(program)) {
						Msg.showInfo(this, null, ReaiPluginPackage.WINDOW_PREFIX + "Create new Analysis for Binary",
								"Program has not been auto-analyzed by Ghidra yet. Please run auto-analysis first.");
						return;
					}
					var analysisOptionsDialog = RevEngAIAnalysisOptionsDialog.withModelsFromServer(program, getRevengService());
					tool.showDialog(analysisOptionsDialog);
                    var options = analysisOptionsDialog.getOptionsFromUI();
                    if (options == null) {
                        loggingService.info("Analysis creation cancelled");
                        return;
                    }
                    var reService = tool.getService(GhidraRevengService.class);

                    var task = new StartAnalysisTask(program, options, reService, analysisLogComponent);
                    task.addTaskListener(new TaskListener() {
                        @Override
                        public void taskCompleted(Task task) {
                            StartAnalysisTask at = (StartAnalysisTask) task;
                            tool.firePluginEvent(
                                    new RevEngAIAnalysisStatusChangedEvent(
                                            "RevEng.AI Analysis",
                                            at.getProgramWithBinaryID(),
                                            AnalysisStatus.Queued)
                            );
                        }

                        @Override
                        public void taskCancelled(Task task) {

                        }
                    });

                    var builder = TaskBuilder.withTask(task);
                    builder.launchInBackground(analysisLogComponent.getTaskMonitor());
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

		if (!getRevengService().isKnownProgram(program)){
			var maybeBinID = getRevengService().getBinaryIDFor(program);
			if (maybeBinID.isEmpty()){
				Msg.info(this, "Program has no saved binary ID");
				return;
			}
			var binID = maybeBinID.get();
			AnalysisStatus status = getRevengService().pollStatus(binID);
			var analysisID = getRevengService().getApi().getAnalysisIDfromBinaryID(binID);
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
        var addr = context.getAddress();
        if (addr == null) {
            return Optional.empty();
        }
		return Optional.ofNullable(context.getProgram().getFunctionManager().getFunctionContaining(addr));
	}

    @Override
    public void processEvent(PluginEvent event) {
        super.processEvent(event);
        if (Objects.requireNonNull(event) instanceof RevEngAIAnalysisStatusChangedEvent e) {
            switch (e.getStatus()) {
                case Complete -> {
                    if (!getRevengService().isProgramAnalysed(e.getProgram())) {
                        // An analysis became just finished and the associated information isn't stored in the program
                        // yet
                        getRevengService().registerFinishedAnalysisForProgram(e.getProgramWithBinaryID());
                        Msg.showInfo(this, null, ReaiPluginPackage.WINDOW_PREFIX + "Analysis Complete",
                                "Analysis for " + e.getProgram() + "completed successfully");
                    }
                    tool.firePluginEvent(
                            new RevEngAIAnalysisResultsLoaded(
                                    "CorePlugin",
                                    e.getProgramWithBinaryID()
                            )
                    );
                }
                case Error -> {
                    Msg.showError(this, null, ReaiPluginPackage.WINDOW_PREFIX + "Analysis Error",
                            "Analysis for binary " + e.getBinaryID() + " finished with error");
                }
                // Inform the analysis log component about an analysis that hasn't finished yet
                // to start monitoring it
                default -> analysisLogComponent.processEvent(e);
            }
        }
    }
}
