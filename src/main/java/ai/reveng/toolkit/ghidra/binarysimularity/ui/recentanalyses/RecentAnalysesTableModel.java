package ai.reveng.toolkit.ghidra.binarysimularity.ui.recentanalyses;

import ai.reveng.toolkit.ghidra.binarysimularity.ui.autoanalysis.AutoAnalysisResultsTableModel;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.types.*;
import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;
import docking.widgets.table.threaded.ThreadedTableModelStub;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class RecentAnalysesTableModel extends ThreadedTableModelStub<AnalysisResult> {
    private final BinaryHash hash;

    public RecentAnalysesTableModel(PluginTool tool, BinaryHash hash) {
        super("Recent Analyses Table Model", tool);
        this.hash = hash;
    }

    @Override
    protected void doLoad(Accumulator<AnalysisResult> accumulator, TaskMonitor monitor) throws CancelledException {
        var revEngAIService = serviceProvider.getService(GhidraRevengService.class);
        revEngAIService.searchForHash(hash).forEach(
                result -> {
                    try {
                        // We don't know if we own this Analysis, so we check if we can get the status
                        // if it fails with an APIAuthenticationException, we don't own it
                        revEngAIService.getApi().status(result.binary_id());
                    } catch (APIAuthenticationException e) {
                        // We got an exception, don't add this result to the list
                        return;
                    }
                    accumulator.add(result);
                }
        );
    }

    @Override
    protected TableColumnDescriptor<AnalysisResult> createTableColumnDescriptor() {
        TableColumnDescriptor<AnalysisResult> descriptor = new TableColumnDescriptor<>();
        descriptor.addVisibleColumn(new AbstractDynamicTableColumn<AnalysisResult, BinaryID, Object>() {
            @Override
            public String getColumnName() {
                return "Analysis ID";
            }

            @Override
            public BinaryID getValue(AnalysisResult rowObject, Settings settings, Object data, ServiceProvider serviceProvider) throws IllegalArgumentException {
                return rowObject.binary_id();
            }
        });
        descriptor.addVisibleColumn(new AbstractDynamicTableColumn<AnalysisResult, String, Object>() {
            @Override
            public String getColumnName() {
                return "Binary Name";
            }

            @Override
            public String getValue(AnalysisResult rowObject, Settings settings, Object data, ServiceProvider serviceProvider) throws IllegalArgumentException {
                return rowObject.binary_name();
            }
        });

        descriptor.addVisibleColumn(new AbstractDynamicTableColumn<AnalysisResult, String, Object>() {
            @Override
            public String getColumnName() {
                return "Creation Time";
            }

            @Override
            public String getValue(AnalysisResult rowObject, Settings settings, Object data, ServiceProvider serviceProvider) throws IllegalArgumentException {
                return rowObject.creation();
            }
        });

        descriptor.addVisibleColumn(new AbstractDynamicTableColumn<AnalysisResult, AnalysisStatus, Object>() {
            @Override
            public String getColumnName() {
                return "Status";
            }

            @Override
            public AnalysisStatus getValue(AnalysisResult rowObject, Settings settings, Object data, ServiceProvider serviceProvider) throws IllegalArgumentException {
                return rowObject.status();
            }
        });


        return descriptor;
    }
}
