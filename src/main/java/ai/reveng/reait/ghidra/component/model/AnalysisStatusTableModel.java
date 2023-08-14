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
		this.columnNames = new String[] {"Creation", "Model", "Hash", "Status"};
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

}
