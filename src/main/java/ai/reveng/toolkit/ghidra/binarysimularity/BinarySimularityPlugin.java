/* ###
 * IP: GHIDRA
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
package ai.reveng.toolkit.ghidra.binarysimularity;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.io.File;

import org.json.JSONObject;

import ai.reveng.toolkit.ghidra.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.binarysimularity.actions.RenameFromSimilarFunctionsAction;
import ai.reveng.toolkit.ghidra.binarysimularity.ui.autoanalysis.AutoAnalysisDockableDialog;
import ai.reveng.toolkit.ghidra.core.services.api.AnalysisOptions;
import ai.reveng.toolkit.ghidra.core.services.api.ApiResponse;
import ai.reveng.toolkit.ghidra.core.services.api.ApiService;
import ai.reveng.toolkit.ghidra.core.services.function.export.ExportFunctionBoundariesService;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;

/**
 * This plugin provides features for performing binary code similarity using the
 * RevEng.AI API
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = ReaiPluginPackage.NAME,
	category = PluginCategoryNames.DIFF,
	shortDescription = "Support for Binary Simularity Featrues of RevEng.AI Toolkit.",
	description = "Enable features that support binary simlularity operations, including binary upload, and auto-renaming",
	servicesRequired = { ApiService.class, ProgramManager.class, ExportFunctionBoundariesService.class }
)
//@formatter:on
public class BinarySimularityPlugin extends ProgramPlugin {
	private ApiService apiService;
	private ExportFunctionBoundariesService exportFunctionBoundariesService;

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public BinarySimularityPlugin(PluginTool tool) {
		super(tool);

		setupActions();
	}

	private void setupActions() {
		DockingAction uploadBinary = new DockingAction("Upload Binary", getName()) {

			@Override
			public void actionPerformed(ActionContext context) {
				System.out.println("Upload bin");
				File binFile;

				System.out.println("Attempting to read:" + currentProgram.getExecutablePath());

				if (new File(currentProgram.getExecutablePath()).exists()) {
					binFile = new File(currentProgram.getExecutablePath());
				} else {
					GhidraFileChooser fileChooser = new GhidraFileChooser(null);
					fileChooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);

					binFile = fileChooser.getSelectedFile(true);
					fileChooser.dispose();
				}

				if (binFile == null) {
					System.err.println("No file selected for upload");
					Msg.showError(binFile, null, ReaiPluginPackage.WINDOW_PREFIX + "Upload Binary",
							"No Binary Selected", null);
					return;
				}
				
				String baseAddr = currentProgram.getImageBase().toString("0x");
				
				JSONObject symbols = new JSONObject();
				symbols.put("base_addr", baseAddr);
				symbols.put("functions", exportFunctionBoundariesService.getFunctionsArray());

				String hash = apiService.upload(binFile.toPath()).getJsonObject().getString("sha_256_hash");
				
				AnalysisOptions ao = new AnalysisOptions
						.Builder()
						.fileName(binFile.toPath().toFile().getName())
						.binHash(hash)
						.symbols(symbols)
						.build();
				
				ApiResponse res = apiService.analyse(ao);
				
				if (res.getStatusCode() == 200) {
					int binID = res.getJsonObject().getInt("binary_id");
					System.out.println("Got binary_id: " + binID);
					tool.getOptions("Preferences").setLong(ReaiPluginPackage.OPTION_KEY_BINID, binID);
				}
				System.out.println(res);
			}

		};
		uploadBinary.setMenuBarData(new MenuData(new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "Upload Binary" },
				ReaiPluginPackage.NAME));
		uploadBinary.setPopupMenuData(new MenuData(new String[] { "Upload Binary" }, ReaiPluginPackage.NAME));
		tool.addAction(uploadBinary);

		DockingAction checkStatusAction = new DockingAction("Check Analysis Status", getName()) {

			@Override
			public void actionPerformed(ActionContext context) {
				long bid = tool.getOptions("Preferences").getLong(ReaiPluginPackage.OPTION_KEY_BINID, 0xffff);
				ApiResponse res = apiService.status(bid);
				Msg.showInfo(this, null, ReaiPluginPackage.WINDOW_PREFIX + "Check Analysis Status",
						"Status: " + res.getJsonObject().get("status"));
			}
		};
		checkStatusAction.setMenuBarData(new MenuData(
				new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "Check Analysis Status" }, ReaiPluginPackage.NAME));
		checkStatusAction
				.setPopupMenuData(new MenuData(new String[] { "Check Analysis Status" }, ReaiPluginPackage.NAME));
		tool.addAction(checkStatusAction);

		RenameFromSimilarFunctionsAction rsfAction = new RenameFromSimilarFunctionsAction(getName(), getTool());
		rsfAction.setPopupMenuData(
				new MenuData(new String[] { "Rename From Similar Functions" }, ReaiPluginPackage.NAME));
		// default to ctrl+shift R
		rsfAction.setKeyBindingData(
				new KeyBindingData(KeyEvent.VK_R, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK));
		tool.addAction(rsfAction);

		DockingAction autoAnalysisAction = new DockingAction("Auto Analysis Similar Functions", this.getName()) {

			@Override
			public void actionPerformed(ActionContext context) {
				AutoAnalysisDockableDialog autoAnalyse = new AutoAnalysisDockableDialog(tool);
				tool.showDialog(autoAnalyse);

			}
		};
		autoAnalysisAction.setMenuBarData(
				new MenuData(new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "Auto Analyse Binary Symbols" },
						ReaiPluginPackage.NAME));
		autoAnalysisAction
				.setPopupMenuData(new MenuData(new String[] { "Auto Analyse Binary Symbols" }, ReaiPluginPackage.NAME));
		// default to ctrl+shift A
		autoAnalysisAction.setKeyBindingData(
				new KeyBindingData(KeyEvent.VK_A, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK));
		tool.addAction(autoAnalysisAction);
	}

	@Override
	public void init() {
		super.init();
		
		apiService = tool.getService(ApiService.class);
		exportFunctionBoundariesService = tool.getService(ExportFunctionBoundariesService.class);
	}
}
