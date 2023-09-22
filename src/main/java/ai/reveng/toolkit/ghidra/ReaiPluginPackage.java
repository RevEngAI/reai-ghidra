package ai.reveng.toolkit.ghidra;

import ghidra.framework.plugintool.util.PluginPackage;
import resources.ResourceManager;

/**
 * Top-level package object for RevEng.AI Ghidra Plugins
 */
public class ReaiPluginPackage extends PluginPackage {
	public static final String NAME = "RevEng.AI";
	public static final String PREFIX = "RevEngAI.";
	public static final String MENU_GROUP_NAME = "RevEngAI Toolkit";
	public static final String WINDOW_PREFIX = "RevEng.AI Toolkit: ";
	/*
	 * Below are the keys used to store/retrieve key-value pairs in Ghidra
	 * preferences
	 */
	public static final String OPTION_KEY_APIKEY = PREFIX + "API Key";
	public static final String OPTION_KEY_HOSTNAME = PREFIX + "Hostname";
	public static final String OPTION_KEY_MODEL = PREFIX + "Model";

	/**
	 * Create a Top Level Plugin Package that uses the RevEng.AI logo
	 */
	public ReaiPluginPackage() {
		super(NAME, ResourceManager.loadImage("images/icon.png"), "AI Assisted Binary Analysis");
	}
}