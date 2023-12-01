package ai.reveng.toolkit.ghidra.core.services.importer;

import java.io.File;

import ai.reveng.toolkit.ghidra.core.CorePlugin;
import ghidra.framework.plugintool.ServiceInfo;

@ServiceInfo(defaultProvider = CorePlugin.class, description = "Import and analysis from the RevEng.AI portal for use in the integration")
public interface AnalysisImportService {
	/**
	 * Setup the project from an exported analysis
	 * @param filePath
	 */
	public void importFromJSON(File jsonFile);
}
