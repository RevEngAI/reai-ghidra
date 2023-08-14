package ai.reveng.reait.ghidra;

import ghidra.framework.plugintool.util.PluginPackage;
import resources.ResourceManager;

/**
 * Top-level package object for RevEng.AI Ghidra Plugins
 */
public class REAIPluginPackage extends PluginPackage {
	public static final String NAME = "RevEng.AI";

	/**
	 * Create a Top Level Plugin Package that uses the RevEng.AI logo
	 */
	public REAIPluginPackage() {
		super(NAME, ResourceManager.loadImage("images/icon.png"), "AI Assisted Binary Analysis");
	}
}
