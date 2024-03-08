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
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import ai.reveng.toolkit.ghidra.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.core.services.api.ApiService;
import ai.reveng.toolkit.ghidra.core.services.api.ApiServiceImpl;
import ai.reveng.toolkit.ghidra.core.services.configuration.ConfigurationService;
import ai.reveng.toolkit.ghidra.core.services.function.export.ExportFunctionBoundariesService;
import ai.reveng.toolkit.ghidra.core.services.function.export.ExportFunctionBoundariesServiceImpl;
import ai.reveng.toolkit.ghidra.core.services.importer.AnalysisImportService;
import ai.reveng.toolkit.ghidra.core.services.importer.AnalysisImportServiceImpl;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingService;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingServiceImpl;
import ai.reveng.toolkit.ghidra.core.ui.wizard.SetupWizardManager;
import ai.reveng.toolkit.ghidra.core.ui.wizard.SetupWizardStateKey;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.wizard.WizardManager;
import docking.wizard.WizardState;
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
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = ReaiPluginPackage.NAME,
	category = PluginCategoryNames.MISC,
	shortDescription = "Toolkit for using RevEngAI API",
	description = "Toolkit for using RevEng.AI API",
	servicesRequired = { OptionsService.class },
	servicesProvided = { ApiService.class, ExportFunctionBoundariesService.class, AnalysisImportService.class, ReaiLoggingService.class }
)
//@formatter:on
public class CorePlugin extends ProgramPlugin {
	private static final String REAI_WIZARD_RUN_PREF = "REAISetupWizardRun";

	private ApiService apiService;
	private ExportFunctionBoundariesService exportFunctionBoundariesService;
	private AnalysisImportService analysisImportService;
	private ReaiLoggingService loggingService;

	private PluginTool tool;

	public CorePlugin(PluginTool tool) {
		super(tool);

		this.tool = tool;

		loggingService = new ReaiLoggingServiceImpl();
		registerServiceProvided(ReaiLoggingService.class, loggingService);

		String apikey = "invalid";
		String hostname = "unknown";
		String modelname = "unknown";

		String uHome = System.getProperty("user.home");
		String cDir = ".reai";
		String cFileName = "reai.json";
		Path configDirPath = Paths.get(uHome, cDir);
		Path configFilePath = configDirPath.resolve(cFileName);

		// check if we have already have a configfile to read
		if (Files.exists(configFilePath)) {
			// Read and parse the config file as JSON
			JSONParser parser = new JSONParser();
			try (FileReader reader = new FileReader(configFilePath.toString())) {
				JSONObject configObject = (JSONObject) parser.parse(reader);
				JSONObject credsObject = (JSONObject) configObject.get("PLUGIN_SETTINGS");
				apikey = (String) credsObject.get("API_KEY");
				hostname = (String) credsObject.get("HOSTNAME");
				modelname = (String) credsObject.get("MODEL");
				loggingService.info(configObject.toJSONString());

				// update project to use these
				tool.getOptions("Preferences").setString(ReaiPluginPackage.OPTION_KEY_APIKEY, apikey);
				tool.getOptions("Preferences").setString(ReaiPluginPackage.OPTION_KEY_HOSTNAME, hostname);
				tool.getOptions("Preferences").setString(ReaiPluginPackage.OPTION_KEY_MODEL, modelname);
			} catch (FileNotFoundException e) {
				loggingService.error(e.getMessage());
				Msg.showError(this, null, "Load Config", "Unable to find config file");
			} catch (IOException e) {
				loggingService.error(e.getMessage());
				Msg.showError(this, null, "Load Config", "Unable to read config file: " + e.getMessage());
			} catch (ParseException e) {
				loggingService.error(e.getMessage());
				Msg.showError(this, null, "Load Config", "Unable to parse config file: " + e.getMessage());
			}
		} else if (!hasSetupWizardRun()) {
			runSetupWizard();
			setWizardRun();

			apikey = tool.getOptions("Preferences").getString(ReaiPluginPackage.OPTION_KEY_APIKEY, "invalid");
			hostname = tool.getOptions("Preferences").getString(ReaiPluginPackage.OPTION_KEY_HOSTNAME, "unknown");
			modelname = tool.getOptions("Preferences").getString(ReaiPluginPackage.OPTION_KEY_MODEL, "unknown");
		} else {
			Msg.showError(tool, null, "Load config", "Unable to load a config file, or start the wizard");
		}

		apiService = new ApiServiceImpl(hostname, apikey, modelname);
		registerServiceProvided(ApiService.class, apiService);

		exportFunctionBoundariesService = new ExportFunctionBoundariesServiceImpl(tool);
		registerServiceProvided(ExportFunctionBoundariesService.class, exportFunctionBoundariesService);

		analysisImportService = new AnalysisImportServiceImpl(tool);
		registerServiceProvided(AnalysisImportService.class, analysisImportService);

		setupActions();

	}

	private void setupActions() {
		DockingAction runWizard = new DockingAction("Run Setup Wizard", getName()) {

			@Override
			public void actionPerformed(ActionContext context) {
				runSetupWizard();

			}

		};
		runWizard.setMenuBarData(new MenuData(new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "Run Setup Wizard" },
				ReaiPluginPackage.NAME));
		tool.addAction(runWizard);

		DockingAction importAnalysis = new DockingAction("Import Analysis", getName()) {

			@Override
			public void actionPerformed(ActionContext context) {
				GhidraFileChooser fileChooser = new GhidraFileChooser(null);
				fileChooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);

				File jsonFile = fileChooser.getSelectedFile(true);
				fileChooser.dispose();

				if (jsonFile == null) {
					loggingService.error("No analysis selected for import");
					Msg.showError(jsonFile, null, ReaiPluginPackage.WINDOW_PREFIX + "Import Analysis",
							"No Binary Selected", null);
					return;
				}

				analysisImportService.importFromJSON(jsonFile);

				loggingService.info("Successfully imported analysis result");
				Msg.showInfo(jsonFile, null, ReaiPluginPackage.WINDOW_PREFIX + "Import Analysis",
						"Successfully imported analysis result");
			}
		};
		importAnalysis.setMenuBarData(new MenuData(
				new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "Import Analysis" }, ReaiPluginPackage.NAME));
		tool.addAction(importAnalysis);

		DockingAction exportLogfile = new DockingAction("Export Plugin Logs", getName()) {

			@Override
			public void actionPerformed(ActionContext context) {
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
		};
		exportLogfile.setMenuBarData(new MenuData(new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "Export Logs" },
				ReaiPluginPackage.NAME));
		tool.addAction(exportLogfile);
	}

	@Override
	public void init() {
		super.init();

	}

	private boolean hasSetupWizardRun() {
		String value = tool.getOptions("Preferences").getString(REAI_WIZARD_RUN_PREF, "false");
		return Boolean.parseBoolean(value);
	}

	private void setWizardRun() {
		tool.getOptions("Preferences").setString(REAI_WIZARD_RUN_PREF, "true");
	}

	private void runSetupWizard() {
		loggingService.info("First time running setup wizard");
		SetupWizardManager setupManager = new SetupWizardManager(new WizardState<SetupWizardStateKey>(), getTool(),
				loggingService);
		WizardManager wizardManager = new WizardManager("RevEng.ai Setup Wizard", true, setupManager);
		wizardManager.showWizard(tool.getToolFrame());

		return;
	}

}
