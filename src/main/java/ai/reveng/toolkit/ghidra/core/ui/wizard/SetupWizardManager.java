package ai.reveng.toolkit.ghidra.core.ui.wizard;

import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import ai.reveng.toolkit.ghidra.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingService;
import ai.reveng.toolkit.ghidra.core.ui.wizard.panels.UserAvailableModelsPanel;
import ai.reveng.toolkit.ghidra.core.ui.wizard.panels.UserCredentialsPanel;
import docking.wizard.AbstractMagePanelManager;
import docking.wizard.IllegalPanelStateException;
import docking.wizard.MagePanel;
import docking.wizard.WizardState;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;

public class SetupWizardManager extends AbstractMagePanelManager<SetupWizardStateKey> {
	private PluginTool tool;
	private ReaiLoggingService loggingService;

	public SetupWizardManager(WizardState<SetupWizardStateKey> initialState, PluginTool tool, ReaiLoggingService loggingService) {
		super(initialState);
		this.tool = tool;
	}

	@Override
	protected List<MagePanel<SetupWizardStateKey>> createPanels() {
		List<MagePanel<SetupWizardStateKey>> panels = new ArrayList<MagePanel<SetupWizardStateKey>>();
		panels.add(new UserCredentialsPanel(tool));
		panels.add(new UserAvailableModelsPanel());

		return panels;
	}

	@Override
	protected void doFinish() throws IllegalPanelStateException {
		getWizardManager().completed(true);
		String apiKey = (String) getState().get(SetupWizardStateKey.API_KEY);
		String hostname = (String) getState().get(SetupWizardStateKey.HOSTNAME);
		String model = (String) getState().get(SetupWizardStateKey.MODEL);
		
		tool.getOptions("Preferences").setString(ReaiPluginPackage.OPTION_KEY_APIKEY, apiKey);
		tool.getOptions("Preferences").setString(ReaiPluginPackage.OPTION_KEY_HOSTNAME, hostname);
		tool.getOptions("Preferences").setString(ReaiPluginPackage.OPTION_KEY_MODEL, model);
		
		String uHome = System.getProperty("user.home");
		String cDir = ".reai";
		String cFileName = "reai.json";
		Path configDirPath = Paths.get(uHome, cDir);
		Path configFilePath = configDirPath.resolve(cFileName);
		
		// check that our .reai directory exists
		if (!Files.exists(configDirPath)) {
			try {
				Files.createDirectories(configDirPath);
			} catch (IOException e) {
                cleanup();
                return;
            }
		}
		
		// create a new config file, overwritting any existing one
        try (FileWriter file = new FileWriter(configFilePath.toString())) {
            JSONObject defaultConfig = new JSONObject();
            JSONObject pluginSettings = new JSONObject();
            pluginSettings.put("API_KEY", apiKey);
            pluginSettings.put("HOSTNAME", hostname);
            pluginSettings.put("MODEL", model);
            defaultConfig.put("PLUGIN_SETTINGS", pluginSettings);
            file.write(defaultConfig.toJSONString());
            file.flush();
        } catch (IOException e) {
        	cleanup();
            return;
        }
		
		cleanup();

	}

	@Override
	public void cancel() {
		cleanup();
	}

	private void cleanup() {
		List<MagePanel<SetupWizardStateKey>> panels = getPanels();
		for (MagePanel<SetupWizardStateKey> magePanel : panels) {
			magePanel.dispose();
		}
	}

}
