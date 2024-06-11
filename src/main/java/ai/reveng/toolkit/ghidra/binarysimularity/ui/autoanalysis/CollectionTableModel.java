package ai.reveng.toolkit.ghidra.binarysimularity.ui.autoanalysis;

import java.util.ArrayList;
import java.util.List;

import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.types.Collection;

import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;
import docking.widgets.table.threaded.ThreadedTableModelStub;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class CollectionTableModel extends ThreadedTableModelStub<CollectionRowObject> {
	// column indexes
	final static byte NAME = 0;
	final static byte INCLUDE = 1;
	
	private PluginTool plugin;
	
	public CollectionTableModel(PluginTool plugin) {
		super("Collections Table Model", plugin);
		this.plugin = plugin;
	}

	@Override
	protected void doLoad(Accumulator<CollectionRowObject> accumulator, TaskMonitor monitor) throws CancelledException {
		GhidraRevengService apiService = plugin.getService(GhidraRevengService.class);
		List<Collection> res = apiService.collections();
		res.forEach(
				collection -> accumulator.add(new CollectionRowObject(collection.collectionName(), false))
		);

		
	}

	@Override
	protected TableColumnDescriptor<CollectionRowObject> createTableColumnDescriptor() {
		TableColumnDescriptor<CollectionRowObject> descriptor = new TableColumnDescriptor<CollectionRowObject>();
		descriptor.addVisibleColumn(new CollectionNameTableColumn());
		descriptor.addVisibleColumn(new CollectionIncludeTableColumn());
		
		return descriptor;
	}
	
	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		switch(columnIndex) {
			case INCLUDE:
				return true;
			default:
				return false;
		}
	}
	
	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		switch(columnIndex) {
		case INCLUDE:
			if (aValue instanceof Boolean) {
				CollectionRowObject ro = getRowObject(rowIndex);
				ro.setInclude((Boolean) aValue);
				fireTableRowsUpdated(rowIndex, rowIndex);
			}
		default:
			break;
		}
	}
	
	public List<String> getSelectedCollections() {
		List<String> collections = new ArrayList<String>();
		for (CollectionRowObject collection : getAllData()) {
			if (collection.isInclude())
				collections.add(collection.getCollectionName());
		}
		return collections;
	}
	
	private class CollectionNameTableColumn extends AbstractDynamicTableColumn<CollectionRowObject, String, Object> {

		@Override
		public String getColumnName() {
			return "Collection Name";
		}

		@Override
		public String getValue(CollectionRowObject rowObject, Settings settings, Object data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getCollectionName();
		}
	}
	
	private class CollectionIncludeTableColumn extends AbstractDynamicTableColumn<CollectionRowObject, Boolean, Object> {

		@Override
		public String getColumnName() {
			return "Include";
		}

		@Override
		public Boolean getValue(CollectionRowObject rowObject, Settings settings, Object data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.isInclude();
		}
		
	}
}
