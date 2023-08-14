/* ###
 * IP: RevEng.AI
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ai.reveng.reait.ghidra;

import ai.reveng.reait.ghidra.actions.FunctionSimilarityAction;
import ai.reveng.reait.ghidra.actions.UploadCurrentBinaryAction;
import ai.reveng.reait.ghidra.component.ConfigureDockableDialog;
import ai.reveng.reait.ghidra.component.REAITComponentProvider;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;

/**
 * This plugin configures Ghidra to interface with the RevEng.AI API
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = REAIPluginPackage.NAME,
	category = PluginCategoryNames.MISC,
	shortDescription = "Configuration for RevEngAI API",
	description = "Setup interface with the RevEng.AI API"
)
//@formatter:on
public class REAIToolkitPlugin extends ProgramPlugin {

	REAITComponentProvider provider;

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public REAIToolkitPlugin(PluginTool tool) {
		super(tool);

		provider = new REAITComponentProvider(this, "RevEng.AI Toolkit");
	}
	
	private void createDropdownMenu() {
	    UploadCurrentBinaryAction ucbAction = new UploadCurrentBinaryAction("Upload Current Binary", getName());
	    ucbAction.setMenuBarData(new MenuData(new String[] {"RevEngAI Toolkit", "Upload Current Binary"}, null, "reait"));
	    tool.addAction(ucbAction);
	    
	}
	
	@Override
	public void programActivated(Program program) {
		super.programActivated(program);
		
		// init the helper
		REAITHelper helper = REAITHelper.getInstance();
		helper.setFlatAPI(new FlatProgramAPI(this.currentProgram));
	}

	@Override
	public void init() {
		super.init();
		
//		createDropdownMenu();
	}
}
