package ai.reveng.reait.ghidra;

import ghidra.framework.plugintool.util.PluginPackage;
import resources.ResourceManager;

public class REAIPluginPackage extends PluginPackage {
	public static final String NAME = "RevEng.AI";
	
	public REAIPluginPackage() {
		super(NAME, ResourceManager.loadImage("images/icon.png"), "AI Assisted Binary Analysis");
	}
}
