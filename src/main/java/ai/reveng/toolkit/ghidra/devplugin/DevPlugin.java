package ai.reveng.toolkit.ghidra.devplugin;

import ai.reveng.toolkit.ghidra.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import docking.options.OptionsService;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

/**
 * Plugin for development and debug helpers for the RevEng.AI Toolkit
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = ReaiPluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Toolkit for using the RevEng.AI API",
	description = "Toolkit for using RevEng.AI API",
	servicesRequired = { OptionsService.class, GhidraRevengService.class }
)
//@formatter:on
public class DevPlugin extends ProgramPlugin {

	private final RevEngMetadataProvider revEngMetadataProvider;
	private GhidraRevengService apiService;

	public DevPlugin(PluginTool tool) {
		super(tool);
		revEngMetadataProvider = new RevEngMetadataProvider(tool, ReaiPluginPackage.NAME);
		tool.addComponentProvider(revEngMetadataProvider, false);


	}

	@Override
	protected void programActivated(Program program) {
		revEngMetadataProvider.setProgram(program);
	}

	@Override
	protected void locationChanged(ProgramLocation loc) {
		super.locationChanged(loc);
		revEngMetadataProvider.locationChanged(loc);
	}

	@Override
	public void init() {
		super.init();
		this.apiService = tool.getService(GhidraRevengService.class);
	}

}
