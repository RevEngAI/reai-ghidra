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
package ai.reveng.toolkit.ghidra;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import ai.reveng.toolkit.ghidra.actions.RenameFunctionFromSimilarFunctionsAction;
import ai.reveng.toolkit.ghidra.component.AutoAnalyseDockableDialog;
import ai.reveng.toolkit.ghidra.component.RE_AIToolkitComponentProvider;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.Program;

/**
 * This plugin configures Ghidra to interface with the RevEng.AI API
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = RE_AIPluginPackage.NAME,
	category = PluginCategoryNames.MISC,
	shortDescription = "Toolkit for using RevEngAI API",
	description = "Toolkit for using RevEng.AI API"
)
//@formatter:on
public class RE_AIToolkitPlugin extends ProgramPlugin {

	RE_AIToolkitComponentProvider provider;

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public RE_AIToolkitPlugin(PluginTool tool) {
		super(tool);

		provider = new RE_AIToolkitComponentProvider(this, "RevEng.AI Toolkit");
	}

	private void createActions() {
		RenameFunctionFromSimilarFunctionsAction renameFromEmbeddingsAction = new RenameFunctionFromSimilarFunctionsAction("Rename From Similar Functions", tool);
		renameFromEmbeddingsAction.setPopupMenuData(new MenuData(new String[] { "Rename From Similar Functions" }, null, "Reveng.AI"));
		// default to ctrl+shift R
		renameFromEmbeddingsAction.setKeyBindingData(new KeyBindingData(KeyEvent.VK_R, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK));
		
		DockingAction autoAnalysisAction = new DockingAction("Auto Analysis Similar Functions", this.getName()) {
			
			@Override
			public void actionPerformed(ActionContext context) {
				AutoAnalyseDockableDialog autoAnalyse = new AutoAnalyseDockableDialog();
				tool.showDialog(autoAnalyse);
				
			}
		};
		// default to ctrl+shift A
		autoAnalysisAction.setKeyBindingData(new KeyBindingData(KeyEvent.VK_A, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK));

		tool.addAction(renameFromEmbeddingsAction);
		tool.addAction(autoAnalysisAction);
	}

	@Override
	public void programActivated(Program program) {
		super.programActivated(program);

		// init the helper
		RE_AIToolkitHelper helper = RE_AIToolkitHelper.getInstance();
		helper.setFlatAPI(new FlatProgramAPI(this.currentProgram));
	}

	@Override
	public void init() {
		super.init();

//		createDropdownMenu();
		createActions();
	}
}
