package ai.reveng.toolkit.ghidra.core;

import ai.reveng.toolkit.ghidra.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.types.ApiInfo;
import ai.reveng.toolkit.ghidra.core.ui.wizard.SetupWizardManager;
import ai.reveng.toolkit.ghidra.core.ui.wizard.SetupWizardStateKey;
import docking.ActionContext;
import docking.action.builder.ActionBuilder;
import docking.options.OptionsService;
import docking.wizard.WizardManager;
import docking.wizard.WizardState;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;

import java.io.FileNotFoundException;
import java.util.Optional;

/// This plugin  provides the [GhidraRevengService] to interact with the RevEng.AI Platform and the related UI actions.
/// This service can then be retrieved by other plugins to implement their functionality
///
/// This is a separate plugin because it allows easy mocking:
/// If the other plugins are tested in a CI then
/// a custom service can be registered that produces mock responses without hitting the real API
/// This also works for human testing: e.g. we could add a variant of the service that is painfully slow, to make sure
/// that we are never accidentally blocking the swing thread
//@formatter:off
@PluginInfo(
        status = PluginStatus.RELEASED,
        packageName = ReaiPluginPackage.NAME,
        category = PluginCategoryNames.COMMON,
        shortDescription = "Provides the service to interact with the RevEng.AI API",
        description = "Provides the service to interact with the RevEng.AI API",
        servicesRequired = { OptionsService.class, ConsoleService.class},
        servicesProvided = { GhidraRevengService.class }
)
//@formatter:on
public class ServicePlugin extends Plugin {
    private final GhidraRevengService revengService;
    private ApiInfo apiInfo;
    private static final String REAI_PLUGIN_SETUP_MENU_GROUP = "RevEng.AI Setup";


    /**
     * Construct a new Plugin.
     *
     * @param tool PluginTool that will host/contain this plugin.
     */
    public ServicePlugin(PluginTool tool) {
        super(tool);

        // Try to get the API info from the local config, if it's not there, run the setup wizard
        getApiInfoFromConfig().ifPresentOrElse(
                info -> apiInfo = info,
                () -> { runSetupWizard(); apiInfo = getApiInfoFromConfig().orElseThrow();}
        );

        revengService = new GhidraRevengService(apiInfo);
        registerServiceProvided(GhidraRevengService.class, revengService);


        new ActionBuilder("Re-Run Setup Wizard", this.toString())
                .withContext(ActionContext.class)
                .onAction(context ->  {
                    runSetupWizard();
                })
                .menuPath(new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "Configure" })
                .menuGroup(REAI_PLUGIN_SETUP_MENU_GROUP, "100")
                .buildAndInstall(tool);

    }

    private void runSetupWizard() {
//        loggingService.info("First time running setup wizard");
        SetupWizardManager setupManager = new SetupWizardManager(new WizardState<SetupWizardStateKey>(), getTool()
        );
        WizardManager wizardManager = new WizardManager("RevEng.ai Setup Wizard", true, setupManager);
        wizardManager.showWizard(tool.getToolFrame());

        return;
    }


    /**
     * Attempts to generate an {@link ApiInfo} object from the config file
     * @return
     */
    private Optional<ApiInfo> getApiInfoFromConfig(){
        try {
            return Optional.of(ApiInfo.fromConfig());
        } catch (FileNotFoundException e) {
//            loggingService.error(e.getMessage());
            Msg.showError(this, null, "Load Config", "Unable to find RevEng config file");
            return Optional.empty();
        }

    }

}
