package ai.reveng.toolkit.ghidra.binarysimularity.ui.autoanalysis;

import java.util.List;

import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;
import docking.widgets.table.threaded.ThreadedTableModelStub;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class AutoAnalysisResultsTableModel extends ThreadedTableModelStub<AutoAnalysisResultsRowObject> {
	private static final long serialVersionUID = -8437395899512765590L;
	private PluginTool plugin;
	private List<AutoAnalysisResultsRowObject> results;
	
	
	public AutoAnalysisResultsTableModel(PluginTool plugin) {
		super("Collections Table Model", plugin);
		this.plugin = plugin;
	}

	@Override
	protected void doLoad(Accumulator<AutoAnalysisResultsRowObject> accumulator, TaskMonitor monitor)
			throws CancelledException {
		return;
	}

	@Override
	protected TableColumnDescriptor<AutoAnalysisResultsRowObject> createTableColumnDescriptor() {
		TableColumnDescriptor<AutoAnalysisResultsRowObject> descriptor = new TableColumnDescriptor<AutoAnalysisResultsRowObject>();
		descriptor.addVisibleColumn(new AutoanalysisResultSrcSymbolTableColumn());
		descriptor.addVisibleColumn(new AutoanalysisResultDstSymbolTableColumn());
		descriptor.addVisibleColumn(new AutoanalysisResultSuccessfulTableColumn());
		descriptor.addVisibleColumn(new AutoanalysisResultReasonTableColumn());
		return descriptor;
	}
	
	public void batch(List<AutoAnalysisResultsRowObject> results) {
		for (AutoAnalysisResultsRowObject ro : results) {
			this.addObject(ro);
		}
	}
	
	private class AutoanalysisResultSrcSymbolTableColumn extends AbstractDynamicTableColumn<AutoAnalysisResultsRowObject, String, Object> {

		@Override
		public String getColumnName() {
			return "Source Symbol";
		}

		@Override
		public String getValue(AutoAnalysisResultsRowObject rowObject, Settings settings, Object data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getSrcSymbol();
		}
		
	}
	
	private class AutoanalysisResultDstSymbolTableColumn extends AbstractDynamicTableColumn<AutoAnalysisResultsRowObject, String, Object> {

		@Override
		public String getColumnName() {
			return "Destination Symbol";
		}

		@Override
		public String getValue(AutoAnalysisResultsRowObject rowObject, Settings settings, Object data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getDstSymbol();
		}
		
	}
	
	private class AutoanalysisResultSuccessfulTableColumn extends AbstractDynamicTableColumn<AutoAnalysisResultsRowObject, Boolean, Object> {

		@Override
		public String getColumnName() {
			return "Successful";
		}

		@Override
		public Boolean getValue(AutoAnalysisResultsRowObject rowObject, Settings settings, Object data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.isSuccessful();
		}
		
	}
	
	private class AutoanalysisResultReasonTableColumn extends AbstractDynamicTableColumn<AutoAnalysisResultsRowObject, String, Object> {

		@Override
		public String getColumnName() {
			return "Reason";
		}

		@Override
		public String getValue(AutoAnalysisResultsRowObject rowObject, Settings settings, Object data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getReason();
		}
		
	}
	
	

}
