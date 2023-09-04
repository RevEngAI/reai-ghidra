package ai.reveng.toolkit.ghidra;

import ghidra.framework.plugintool.util.PluginPackage;
import resources.ResourceManager;

/**
 * Top-level package object for RevEng.AI Ghidra Plugins
 */
public class ReaiPluginPackage extends PluginPackage {
	public static final String NAME = "RevEng.AI";
	public static final String WINDOW_PREFIX="RevEng.AI Toolkit: ";

	/**
	 * Create a Top Level Plugin Package that uses the RevEng.AI logo
	 */
	public ReaiPluginPackage() {
		super(NAME, ResourceManager.loadImage("images/icon.png"), "AI Assisted Binary Analysis");
	}
}