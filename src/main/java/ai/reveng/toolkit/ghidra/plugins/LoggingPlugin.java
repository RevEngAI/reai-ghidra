package ai.reveng.toolkit.ghidra.plugins;


import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingService;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingToConsole;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;

@PluginInfo(
        status = PluginStatus.RELEASED,
        packageName = ReaiPluginPackage.NAME,
        category = PluginCategoryNames.COMMON,
        shortDescription = "Logging service provider for the RevEng.AI plugins",
        description = "Logging service provider for the RevEng.AI plugins",
        servicesRequired = {ConsoleService.class},
        servicesProvided = {ReaiLoggingService.class}

)
public class LoggingPlugin extends ProgramPlugin {
    private final ReaiLoggingToConsole loggingService;
    public LoggingPlugin(PluginTool plugintool) {
        super(plugintool);
        loggingService = new ReaiLoggingToConsole(null);
        registerServiceProvided(ReaiLoggingService.class, loggingService);
    }

    @Override
    protected void init() {
        // Services that we depend on are available now
        super.init();
        ConsoleService consoleService = tool.getService(ConsoleService.class);
        loggingService.setConsoleService(consoleService);
    }
}
