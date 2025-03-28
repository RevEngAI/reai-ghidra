package ai.reveng.toolkit.ghidra.binarysimilarity.ui.functionsimilarity;

import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.types.BoxPlot;
import ai.reveng.toolkit.ghidra.core.services.api.types.GhidraFunctionMatch;
import ai.reveng.toolkit.ghidra.core.services.api.types.GhidraFunctionMatchWithSignature;
import ai.reveng.toolkit.ghidra.core.services.api.types.binsync.FunctionArtifact;
import ai.reveng.toolkit.ghidra.core.services.api.types.binsync.FunctionDataTypeMessage;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingService;
import docking.widgets.table.TableColumnDescriptor;
import docking.widgets.table.threaded.ThreadedTableModelStub;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.Optional;

import static ai.reveng.toolkit.ghidra.Utils.addRowToDescriptor;

/**
 * Models a valid entry in the Function Rename Table
 */
public class CanidateFunctionModel extends ThreadedTableModelStub<GhidraFunctionMatchWithSignature> {

	private static final long serialVersionUID = -5451991421127501071L;
	private Function functionUnderReview;
	private final PluginTool pluginTool;
	private boolean limitToSignaturesAvailable;
	private boolean limitToDebugSymbols;
	private int results = 5;
	private Double distance = 0.2;

	public CanidateFunctionModel(PluginTool plugin) {
		super("Candidate Function Model", plugin);
		this.pluginTool = plugin;
		this.functionUnderReview = null;
	}

	public void setFunctionUnderReview(Function functionUnderReview) {
		this.functionUnderReview = functionUnderReview;
		reload();
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

		addRowToDescriptor(descriptor, "Similarity", Double.class, (row) -> row.functionMatch().similarity());
		addRowToDescriptor(descriptor, "Confidence", Double.class,
				(row) -> row.nameScore().map(BoxPlot::average).orElse(null)
		);
		addRowToDescriptor(descriptor, "Binary Name", String.class, (row) -> row.functionMatch().nearest_neighbor_binary_name());
		addRowToDescriptor(descriptor, "Debug Info", Boolean.class, (row) -> row.functionMatch().nearest_neighbor_debug());

		addRowToDescriptor(descriptor, "Function ID", false, Long.class, (row) -> row.functionMatch().nearest_neighbor_id().value());
		addRowToDescriptor(descriptor, "Binary ID", false, Integer.class, (row) -> row.functionMatch().nearest_neighbor_binary_id().value());

		return descriptor;
	}


	@Override
	protected void doLoad(Accumulator<GhidraFunctionMatchWithSignature> accumulator, TaskMonitor monitor) throws CancelledException {

		if (functionUnderReview == null) {
			return;
		}
		GhidraRevengService revengService = serviceProvider.getService(GhidraRevengService.class);

		monitor.setMaximum(results);
		monitor.setProgress(0);
		monitor.setMessage("Searching for similar functions to " + functionUnderReview.getName());
		var matches = revengService.getSimilarFunctions(functionUnderReview, distance, results, limitToDebugSymbols);
		if (matches.isEmpty()){
			this.pluginTool.getService(ReaiLoggingService.class).warn("No matches found for function " + functionUnderReview.getName());
		} else{
			this.pluginTool.getService(ReaiLoggingService.class).info("Found " + matches.size() + " matches for function " + functionUnderReview.getName());
		}
		for (GhidraFunctionMatch match : matches) {
			monitor.checkCancelled();
			var functionSignature = revengService.getFunctionSignatureArtifact(
					match.functionMatch().nearest_neighbor_binary_id(),
					match.functionMatch().nearest_neighbor_id()
			);
			if (limitToSignaturesAvailable && functionSignature.isEmpty()){
				continue;
			}
			BoxPlot namescore = null;
			if (match.functionMatch().nearest_neighbor_debug()){
				namescore = revengService.getNameScoreForMatch(match);

			}
			accumulator.add(
					new GhidraFunctionMatchWithSignature(
							match.function(), match.functionMatch(), functionSignature, Optional.ofNullable(namescore))
			);
			monitor.incrementProgress(1);
		}
	}


	public void setLimitToSignaturesAvailable(boolean selected) {
		limitToSignaturesAvailable = selected;
	}

	public void setLimitToDebugSymbols(boolean selected) {
		limitToDebugSymbols = selected;
	}

	public void setNumResults(int numResults) {
		results = numResults;
	}

	public void setSimilarity(double similarity) {
		distance = 1 - similarity;
	}
}