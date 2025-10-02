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
package ai.reveng.toolkit.ghidra.plugins;

import ai.reveng.toolkit.ghidra.core.RevEngAIAnalysisResultsLoaded;
import ai.reveng.toolkit.ghidra.core.RevEngAIAnalysisStatusChangedEvent;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.about.AboutDialog;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.analysiscreation.RevEngAIAnalysisOptionsDialog;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.misc.AnalysisLogComponent;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.recentanalyses.RecentAnalysisDialog;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.help.HelpDialog;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.types.*;

import ai.reveng.toolkit.ghidra.core.services.function.export.ExportFunctionBoundariesService;
import ai.reveng.toolkit.ghidra.core.services.function.export.ExportFunctionBoundariesServiceImpl;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingService;
import ai.reveng.toolkit.ghidra.core.tasks.StartAnalysisTask;
import ai.reveng.toolkit.ghidra.core.types.ProgramWithBinaryID;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.builder.ActionBuilder;
import docking.widgets.OptionDialog;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.*;
import docking.options.OptionsService;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.Msg;
import ghidra.util.task.TaskBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;

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
	servicesRequired = { OptionsService.class, ReaiLoggingService.class, GhidraRevengService.class},
	servicesProvided = { ExportFunctionBoundariesService.class },
	eventsConsumed = { RevEngAIAnalysisStatusChangedEvent.class}
)
//@formatter:on
public class AnalysisManagementPlugin extends ProgramPlugin {
	private static final String REAI_ANALYSIS_MANAGEMENT_MENU_GROUP = "RevEng.AI Analysis Management";
	private static final String REAI_PLUGIN_PORTAL_MENU_GROUP = "RevEng.AI Portal";
    private static final Logger log = LoggerFactory.getLogger(AnalysisManagementPlugin.class);

    // Store references to actions that need to be refreshed
    private DockingAction createNewAction;
    private DockingAction attachToExistingAction;
    private DockingAction detachAction;
    private DockingAction checkStatusAction;
    private DockingAction viewInPortalAction;

    private GhidraRevengService revengService;
	private ExportFunctionBoundariesService exportFunctionBoundariesService;
	private AnalysisLogComponent analysisLogComponent;

	private PluginTool tool;


	public AnalysisManagementPlugin(PluginTool tool) {
		super(tool);

		this.tool = tool;


        exportFunctionBoundariesService = new ExportFunctionBoundariesServiceImpl(tool);
        registerServiceProvided(ExportFunctionBoundariesService.class, exportFunctionBoundariesService);

    }

    @Override
    public void init() {
        ReaiLoggingService loggingService = tool.getService(ReaiLoggingService.class);

        // Install analysis log viewer
        analysisLogComponent = new AnalysisLogComponent(tool);
        tool.addComponentProvider(analysisLogComponent, false);

        revengService = Objects.requireNonNull(tool.getService(GhidraRevengService.class));

        setupActions();

        loggingService.info("CorePlugin initialized");
    }

	private void setupActions() {





        createNewAction = new ActionBuilder("Create new", this.getName())
                .enabledWhen(context -> {
                    var currentProgram = tool.getService(ProgramManager.class).getCurrentProgram();
                    if (currentProgram == null) {
                        tool.getService(ReaiLoggingService.class).info("Create new action disabled: No current program");
                        return false;
                    }
                    boolean isKnown = revengService.isKnownProgram(currentProgram);
                    boolean shouldEnable = !isKnown;
                    tool.getService(ReaiLoggingService.class).info("Create new action enabled: " + shouldEnable + " (program: " + currentProgram.getName() + ", isKnown: " + isKnown + ")");
                    return shouldEnable;
                })
                .onAction(context -> {
                    var program = tool.getService(ProgramManager.class).getCurrentProgram();
                    if (!GhidraProgramUtilities.isAnalyzed(program)) {
                        Msg.showInfo(this, null, ReaiPluginPackage.WINDOW_PREFIX + "Create new",
                                "Program has not been auto-analyzed by Ghidra yet. Please run auto-analysis first.");
                        return;
                    }
                    var ghidraService = tool.getService(GhidraRevengService.class);
                    var dialog = RevEngAIAnalysisOptionsDialog.withModelsFromServer(program, ghidraService);
                    tool.showDialog(dialog);
                    var analysisOptions = dialog.getOptionsFromUI();
                    if (analysisOptions != null) {
                        // User clicked OK
                        // Prepare Task that starts the analysis (uploading the binary and registering the analysis)
                        var task = new StartAnalysisTask(program, analysisOptions, revengService, analysisLogComponent, tool);
                        // Launch in Background
                        var builder = TaskBuilder.withTask(task);
                        analysisLogComponent.setVisible(true);
                        builder.launchInBackground(analysisLogComponent.getTaskMonitor());
                        // The task will fire the RevEngAIAnalysisStatusChangedEvent event when done
                        // which is then picked up by the AnalysisManagementPlugin and forwarded to the AnalysisLogComponent
                        tool.getService(ReaiLoggingService.class).info("Started analysis: ");
                    } else {
                        // User clicked Cancel
                        tool.getService(ReaiLoggingService.class).info("Create new analysis dialog cancelled by user");
                    }


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
                        tool.getService(ReaiLoggingService.class).info("Attach to existing action disabled: No current program");
                        return false;
                    }
                    boolean isKnown = revengService.isKnownProgram(currentProgram);
                    boolean shouldEnable = !isKnown;
                    tool.getService(ReaiLoggingService.class).info("Attach to existing action enabled: " + shouldEnable + " (program: " + currentProgram.getName() + ", isKnown: " + isKnown + ")");
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
                        tool.getService(ReaiLoggingService.class).info("Detach action disabled: No current program");
                        return false;
                    }
                    boolean isKnown = revengService.isKnownProgram(currentProgram);
                    tool.getService(ReaiLoggingService.class).info("Detach action enabled: " + isKnown + " (program: " + currentProgram.getName() + ", isKnown: " + isKnown + ")");
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
                        tool.getService(ReaiLoggingService.class).info("Check status action disabled: No current program");
                        return false;
                    }
                    boolean isKnown = revengService.isKnownProgram(currentProgram);
                    tool.getService(ReaiLoggingService.class).info("Check status action enabled: " + isKnown + " (program: " + currentProgram.getName() + ", isKnown: " + isKnown + ")");
                    return isKnown;
                })
				.onAction(context -> {
					var currentProgram = tool.getService(ProgramManager.class).getCurrentProgram();
					var binID = revengService.getBinaryIDFor(currentProgram).orElseThrow();
					var analysisID = revengService.getApi().getAnalysisIDfromBinaryID(binID);
					var logs = revengService.getAnalysisLog(analysisID);
					analysisLogComponent.setLogs(logs);
					AnalysisStatus status = revengService.pollStatus(binID);
                    tool.getService(ReaiLoggingService.class).info("Check Status: " + status);
					Msg.showInfo(this, null, ReaiPluginPackage.WINDOW_PREFIX + "Check status",
							"Status of analysis " + analysisID.id() + ": " + status);
				})
				.menuPath(new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "Analysis", "Check status" })
				.menuGroup(REAI_ANALYSIS_MANAGEMENT_MENU_GROUP, "400")
				.buildAndInstall(tool);

        viewInPortalAction = new ActionBuilder("View in portal", this.getName())
                .enabledWhen(context -> {
                    var currentProgram = tool.getService(ProgramManager.class).getCurrentProgram();
                    if (currentProgram == null) {
                        tool.getService(ReaiLoggingService.class).info("View in portal action disabled: No current program");
                        return false;
                    }
                    boolean isKnown = revengService.isKnownProgram(currentProgram);
                    tool.getService(ReaiLoggingService.class).info("View in portal action enabled: " + isKnown + " (program: " + currentProgram.getName() + ", isKnown: " + isKnown + ")");
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
    public void processEvent(PluginEvent event) {
        super.processEvent(event);
        // Forward the event to the analysis log component
        if (event instanceof RevEngAIAnalysisStatusChangedEvent analysisEvent) {
            analysisLogComponent.processEvent(analysisEvent);
            if (analysisEvent.getStatus() == AnalysisStatus.Complete) {
                // If the analysis is complete, we refresh the function signatures from the server
                var program = analysisEvent.getProgramWithBinaryID();
                revengService.registerFinishedAnalysisForProgram(program);
                tool.firePluginEvent(new RevEngAIAnalysisResultsLoaded("AnalysisManagementPlugin", program));
            }
        }
    }

}
