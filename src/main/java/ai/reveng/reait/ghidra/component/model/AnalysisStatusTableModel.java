package ai.reveng.reait.ghidra.component.model;

import java.util.ArrayList;
import java.util.List;

import javax.swing.table.AbstractTableModel;

public class AnalysisStatusTableModel extends AbstractTableModel {
	private static final long serialVersionUID = 3535893419034947188L;

	private List<String[]> data;
	private String[] columnNames;

	public AnalysisStatusTableModel() {
		this.data = new ArrayList<String[]>();
		this.columnNames = new String[] { "Creation", "Model", "Hash", "Status" };
	}

	@Override
	public int getRowCount() {
		return data.size();
	}

	@Override
	public int getColumnCount() {
		return columnNames.length;
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		return data.get(rowIndex)[columnIndex];
	}

	@Override
	public String getColumnName(int column) {
		return columnNames[column];
	}

	public void addRow(String[] row) {
		data.add(row);
		fireTableRowsInserted(data.size() - 1, data.size() - 1);
	}

	public void deleteRow(int rowIndex) {
		if (rowIndex >= 0 && rowIndex < data.size()) {
			data.remove(rowIndex);
			fireTableRowsDeleted(rowIndex, rowIndex);
		}
	}

	public List<String[]> getData() {
		return this.data;
	}

	public void updateValueAt(String value, int rowIndex, int colIndex) {
		if (rowIndex >= 0 && rowIndex < data.size() && colIndex >= 0 && colIndex < columnNames.length) {
			data.get(rowIndex)[colIndex] = (String) value;
			fireTableCellUpdated(rowIndex, colIndex);
		}
	}

	public void clearData() {
		int oldSize = data.size();
		data.clear();
		if (oldSize > 0) {
			fireTableRowsDeleted(0, oldSize - 1);
		}
	}

}
