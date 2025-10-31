package ai.reveng.toolkit.ghidra.plugins;

import ai.reveng.toolkit.ghidra.binarysimilarity.ui.about.AboutDialog;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.help.HelpDialog;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.types.ApiInfo;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingService;
import ai.reveng.toolkit.ghidra.core.ui.wizard.SetupWizardManager;
import ai.reveng.toolkit.ghidra.core.ui.wizard.SetupWizardStateKey;
import docking.ActionContext;
import docking.action.builder.ActionBuilder;
import docking.wizard.WizardManager;
import docking.wizard.WizardState;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;
import org.json.JSONException;

import java.io.FileNotFoundException;
import java.util.Optional;

import static ai.reveng.toolkit.ghidra.plugins.ReaiPluginPackage.REAI_OPTIONS_CATEGORY;

@PluginInfo(
        status = PluginStatus.STABLE,
        packageName = ReaiPluginPackage.NAME,
        category = PluginCategoryNames.COMMON,
        shortDescription = "Reai API Service Plugin",
        description = "Provides the Reai API Service to other plugins, and handles the API credential set up",
        servicesProvided = { GhidraRevengService.class }
)
public class ReaiAPIServicePlugin extends Plugin {
    private final GhidraRevengService revengService;
    private ApiInfo apiInfo;

    private static final String REAI_PLUGIN_SETUP_MENU_GROUP = "RevEng.AI Setup";
    public static final String REAI_WIZARD_RUN_PREF = "REAISetupWizardRun";


    /**
     * Construct a new Plugin.
     *
     * @param tool PluginTool that will host/contain this plugin.
     */
    public ReaiAPIServicePlugin(PluginTool tool) {
        super(tool);

        tool.getOptions(REAI_OPTIONS_CATEGORY).registerOption(REAI_WIZARD_RUN_PREF, "false", null, "If the setup wizard has been run");

        // Try to get API info from multiple sources before running setup wizard
        // 1. First try from config file
        // 2. Then try from tool options (previously entered in wizard)
        // 3. Only run setup wizard if neither source has valid credentials
        Optional<ApiInfo> apiInfoOpt = getApiInfoFromConfig()
                .or(() -> getApiInfoFromToolOptions());

        if (apiInfoOpt.isPresent()) {
            apiInfo = apiInfoOpt.get();
        } else {
            runSetupWizard();
            // After wizard, try to get API info again from tool options or config
            apiInfo = getApiInfoFromToolOptions()
                    .or(() -> getApiInfoFromConfig())
                    .orElseThrow(() -> new RuntimeException("Setup wizard completed but no valid API info found"));
        }
        revengService = new GhidraRevengService(apiInfo);
        registerServiceProvided(GhidraRevengService.class, revengService);

        setupActions();
    }

    /**
     * Attempts to generate an {@link ApiInfo} object from the config file
     * @return
     */
    private Optional<ApiInfo> getApiInfoFromConfig(){
        var loggingService = tool.getService(ReaiLoggingService.class);
        try {
            return Optional.of(ApiInfo.fromConfig());
        } catch (FileNotFoundException e) {
            loggingService.error(e.getMessage());
            return Optional.empty();
        } catch (JSONException e) {
            loggingService.error(e.getMessage());
            Msg.showError(this, null, "Load Config", "Unable to parse RevEng config file: " + e.getMessage());
            return Optional.empty();
        }
    }

    private Optional<ApiInfo> getApiInfoFromToolOptions(){
        var apikey = tool.getOptions(REAI_OPTIONS_CATEGORY).getString(ReaiPluginPackage.OPTION_KEY_APIKEY, "invalid");
        var hostname = tool.getOptions(REAI_OPTIONS_CATEGORY).getString(ReaiPluginPackage.OPTION_KEY_HOSTNAME, "unknown");
        var portalHostname = tool.getOptions(REAI_OPTIONS_CATEGORY).getString(ReaiPluginPackage.OPTION_KEY_PORTAL_HOSTNAME, "unknown");
        if (apikey.equals("invalid") || hostname.equals("unknown") || portalHostname.equals("unknown")){
            return Optional.empty();
        }
        var apiInfo = new ApiInfo(hostname, portalHostname, apikey);

        return Optional.of(apiInfo);
    }

    private void setupActions() {
        new ActionBuilder("Configure", this.toString())
                .withContext(ActionContext.class)
                .onAction(context ->  {
                    runSetupWizard();
                })
                .menuPath(new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "Configure" })
                .menuGroup(REAI_PLUGIN_SETUP_MENU_GROUP, "100")
                .buildAndInstall(tool);

        new ActionBuilder("Help", this.toString())
                .withContext(ActionContext.class)
                .onAction(context ->  {
                    var helpDialog = new HelpDialog(tool);
                    tool.showDialog(helpDialog);
                })
                .menuPath(new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "Help" })
                .menuGroup(REAI_PLUGIN_SETUP_MENU_GROUP, "200")
                .buildAndInstall(tool);

        new ActionBuilder("About", this.toString())
                .withContext(ActionContext.class)
                .onAction(context ->  {
                    var aboutDialog = new AboutDialog(tool);
                    tool.showDialog(aboutDialog);
                })
                .menuPath(new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "About" })
                .menuGroup(REAI_PLUGIN_SETUP_MENU_GROUP, "300")
                .buildAndInstall(tool);

    }

    private void runSetupWizard() {
        tool.getService(ReaiLoggingService.class).info("Running setup wizard");

        // Create wizard state and populate with any existing credentials from tool options
        WizardState<SetupWizardStateKey> wizardState = new WizardState<SetupWizardStateKey>();

        // Pre-populate wizard state with existing credentials if available
        String existingApiKey = tool.getOptions(REAI_OPTIONS_CATEGORY).getString(ReaiPluginPackage.OPTION_KEY_APIKEY, null);
        String existingHostname = tool.getOptions(REAI_OPTIONS_CATEGORY).getString(ReaiPluginPackage.OPTION_KEY_HOSTNAME, null);
        String existingPortalHostname = tool.getOptions(REAI_OPTIONS_CATEGORY).getString(ReaiPluginPackage.OPTION_KEY_PORTAL_HOSTNAME, null);

        // If credentials aren't available from tool options, try loading from config file
        if ((existingApiKey == null || existingApiKey.equals("invalid")) &&
                (existingHostname == null || existingHostname.equals("unknown"))) {
            try {
                ApiInfo configApiInfo = ApiInfo.fromConfig();
                existingApiKey = configApiInfo.apiKey();
                existingHostname = configApiInfo.hostURI().toString();
                existingPortalHostname = configApiInfo.portalURI().toString();
                tool.getService(ReaiLoggingService.class).info("Loaded credentials from configuration file");
            } catch (Exception e) {
                tool.getService(ReaiLoggingService.class).info("No existing configuration file found or could not read it: " + e.getMessage());
            }
        }

        if (existingApiKey != null && !existingApiKey.equals("invalid")) {
            wizardState.put(SetupWizardStateKey.API_KEY, existingApiKey);
        }
        if (existingHostname != null && !existingHostname.equals("unknown")) {
            wizardState.put(SetupWizardStateKey.HOSTNAME, existingHostname);
        }
        if (existingPortalHostname != null && !existingPortalHostname.equals("unknown")) {
            wizardState.put(SetupWizardStateKey.PORTAL_HOSTNAME, existingPortalHostname);
        }

        SetupWizardManager setupManager = new SetupWizardManager(wizardState, getTool());
        WizardManager wizardManager = new WizardManager("RevEng.AI: Configuration", true, setupManager);
        wizardManager.showWizard(tool.getToolFrame());

        return;
    }

    private boolean hasSetupWizardRun() {
        String value = tool.getOptions(REAI_OPTIONS_CATEGORY).getString(REAI_WIZARD_RUN_PREF, "false");
        return Boolean.parseBoolean(value);
    }

    private void setWizardRun() {
        tool.getOptions(REAI_OPTIONS_CATEGORY).setString(REAI_WIZARD_RUN_PREF, "true");
    }

}
