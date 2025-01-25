package ai.reveng.toolkit.ghidra.binarysimilarity.ui.functionsimilarity.models;

import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.types.GhidraFunctionMatch;
import ai.reveng.toolkit.ghidra.core.services.api.types.GhidraFunctionMatchWithSignature;
import ai.reveng.toolkit.ghidra.core.services.api.types.binsync.FunctionArtifact;
import ai.reveng.toolkit.ghidra.core.services.api.types.binsync.FunctionDataTypeMessage;
import docking.widgets.table.TableColumnDescriptor;
import docking.widgets.table.threaded.ThreadedTableModelStub;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import static ai.reveng.toolkit.ghidra.Utils.addRowToDescriptor;

/**
 * Models a valid entry in the Function Rename Table
 */
public class CanidateFunctionModel extends ThreadedTableModelStub<GhidraFunctionMatchWithSignature> {

	private static final long serialVersionUID = -5451991421127501071L;
	private final Function functionUnderReview;

	public CanidateFunctionModel(PluginTool plugin,
								 Function functionUnderReview) {
		super("Candidate Function Model", plugin);
		this.functionUnderReview = functionUnderReview;
	}


	@Override
	protected TableColumnDescriptor<GhidraFunctionMatchWithSignature> createTableColumnDescriptor() {
		TableColumnDescriptor<GhidraFunctionMatchWithSignature> descriptor = new TableColumnDescriptor<>();
		addRowToDescriptor(descriptor,"Name", String.class, (row) -> row.functionMatch().name()
		);

		addRowToDescriptor(
				descriptor,
				"Signature",
				String.class,
				(row) -> row.signature()
						.map(FunctionDataTypeMessage::func_types)
						.map(FunctionArtifact::getSignature)
						.orElse(null)
		);

		addRowToDescriptor(descriptor, "Confidence", Double.class, (row) -> row.functionMatch().confidence());
		addRowToDescriptor(descriptor, "Binary Name", String.class, (row) -> row.functionMatch().nearest_neighbor_binary_name());
		addRowToDescriptor(descriptor, "Debug Info", Boolean.class, (row) -> row.functionMatch().nearest_neighbor_debug());
		addRowToDescriptor(descriptor, "Function ID", Long.class, (row) -> row.functionMatch().nearest_neighbor_id().value());
		addRowToDescriptor(descriptor, "Binary ID", Integer.class, (row) -> row.functionMatch().nearest_neighbor_binary_id().value());


		return descriptor;
	}


	@Override
	protected void doLoad(Accumulator<GhidraFunctionMatchWithSignature> accumulator, TaskMonitor monitor) throws CancelledException {
        GhidraRevengService revengService = serviceProvider.getService(GhidraRevengService.class);

		// TODO: make the settings configurable
		var matches = revengService.getSimilarFunctions(functionUnderReview);
		monitor.checkCancelled();
		for (GhidraFunctionMatch match : matches) {
			var functionSignature = revengService.getFunctionSignatureArtifact(
					match.functionMatch().nearest_neighbor_binary_id(),
					match.functionMatch().nearest_neighbor_id()
			);

			accumulator.add(new GhidraFunctionMatchWithSignature(match.function(), match.functionMatch(), functionSignature));
		}
	}


}