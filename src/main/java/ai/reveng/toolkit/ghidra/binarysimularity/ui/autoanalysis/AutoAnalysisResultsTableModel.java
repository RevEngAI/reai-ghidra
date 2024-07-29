package ai.reveng.toolkit.ghidra.binarysimularity.ui.autoanalysis;

import java.util.List;

import ai.reveng.toolkit.ghidra.core.services.api.types.GhidraFunctionMatch;
import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;
import docking.widgets.table.threaded.ThreadedTableModelStub;
import ghidra.Ghidra;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.ProgramTableModel;
import ghidra.util.task.TaskMonitor;

public class AutoAnalysisResultsTableModel extends ThreadedTableModelStub<GhidraFunctionMatch> implements ProgramTableModel {
	private static final long serialVersionUID = -8437395899512765590L;
	private PluginTool plugin;

	
	public AutoAnalysisResultsTableModel(PluginTool plugin) {
		super("Collections Table Model", plugin);
		this.plugin = plugin;
	}

	@Override
	protected void doLoad(Accumulator<GhidraFunctionMatch> accumulator, TaskMonitor monitor)
			throws CancelledException {
		return;
	}

	@Override
	public void clearData() {
		super.clearData();
	}

	@Override
	protected TableColumnDescriptor<GhidraFunctionMatch> createTableColumnDescriptor() {
		TableColumnDescriptor<GhidraFunctionMatch> descriptor = new TableColumnDescriptor<GhidraFunctionMatch>();
		descriptor.addVisibleColumn(new AutoanalysisResultDstSymbolTableColumn());
		descriptor.addHiddenColumn(new AutoanalysisResultsDestinationSymbolSourceTableColumn());
		descriptor.addHiddenColumn(new AbstractDynamicTableColumn<GhidraFunctionMatch, Address, Object>(){

			@Override
			public String getColumnName() {
				return "Destination Address";
			}

			@Override
			public Address getValue(GhidraFunctionMatch rowObject, Settings settings, Object data, ServiceProvider serviceProvider) throws IllegalArgumentException {
				return rowObject.function().getEntryPoint();
			}
		});

		descriptor.addHiddenColumn(new AbstractDynamicTableColumn<GhidraFunctionMatch, Integer, Object>(){

			@Override
			public String getColumnName() {
				return "Called Functions";
			}

			@Override
			public Integer getValue(GhidraFunctionMatch rowObject, Settings settings, Object data, ServiceProvider serviceProvider) throws IllegalArgumentException {
				return rowObject.function().getCalledFunctions(null).size();
			}
		});


		descriptor.addVisibleColumn(new AutoanalysisResultSrcSymbolTableColumn());
		descriptor.addVisibleColumn(new AutoanalysisResultSrcBinaryTableColumn());
		descriptor.addVisibleColumn(new AutoanalysisResultsConfidenceTableColumn());
//		descriptor.addVisibleColumn(new AutoanalysisResultSuccessfulTableColumn());
//		descriptor.addVisibleColumn(new AutoanalysisResultReasonTableColumn());
		return descriptor;
	}
	
	public void batch(List<GhidraFunctionMatch> results) {
		for (GhidraFunctionMatch ro : results) {
			this.addObject(ro);
		}
	}

	@Override
	public ProgramLocation getProgramLocation(int modelRow, int modelColumn) {
		var row = getRowObject(modelRow);
		return new ProgramLocation(row.function().getProgram(), row.function().getEntryPoint());
	}

	@Override
	public ProgramSelection getProgramSelection(int[] modelRows) {
		return null;
	}

	@Override
	public Program getProgram() {
		return null;
	}

	private class AutoanalysisResultSrcSymbolTableColumn extends AbstractDynamicTableColumn<GhidraFunctionMatch, String, Object> {

		@Override
		public String getColumnName() {
			return "Source Symbol";
		}

		@Override
		public String getValue(GhidraFunctionMatch rowObject, Settings settings, Object data,
								 ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.functionMatch().nearest_neighbor_function_name();
		}
		
	}

	private class AutoanalysisResultSrcBinaryTableColumn extends AbstractDynamicTableColumn<GhidraFunctionMatch, String, Object> {

		@Override
		public String getColumnName() {
			return "Source Binary";
		}

		@Override
		public String getValue(GhidraFunctionMatch rowObject, Settings settings, Object data,
								 ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.functionMatch().nearest_neighbor_binary_name();
		}

	}

	
	private class AutoanalysisResultDstSymbolTableColumn extends AbstractDynamicTableColumn<GhidraFunctionMatch, Function, Object> {

		@Override
		public String getColumnName() {
			return "Destination Symbol";
		}

		@Override
		public Function getValue(GhidraFunctionMatch rowObject, Settings settings, Object data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.function();
		}
		
	}

	private class AutoanalysisResultsConfidenceTableColumn extends AbstractDynamicTableColumn<GhidraFunctionMatch, Double, Object> {

		@Override
		public String getColumnName() {
			return "Confidence";
		}

		@Override
		public Double getValue(GhidraFunctionMatch rowObject, Settings settings, Object data,
								 ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.functionMatch().confidence();
		}

	}

	private class AutoanalysisResultsDestinationSymbolSourceTableColumn extends AbstractDynamicTableColumn<GhidraFunctionMatch, SourceType, Object> {

		@Override
		public String getColumnName() {
			return "Destination Symbol SourceType";
		}

		@Override
		public SourceType getValue(GhidraFunctionMatch rowObject, Settings settings, Object data,
							   ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.function().getSymbol().getSource();
		}

	}

}
