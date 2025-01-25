package ai.reveng.toolkit.ghidra.binarysimilarity.ui.autoanalysis;

import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.types.Collection;
import ai.reveng.toolkit.ghidra.core.services.api.types.GhidraFunctionMatch;
import ai.reveng.toolkit.ghidra.core.services.api.types.GhidraFunctionMatchWithSignature;
import docking.widgets.table.TableColumnDescriptor;
import docking.widgets.table.threaded.ThreadedTableModelStub;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
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

import java.util.List;
import java.util.Map;

import static ai.reveng.toolkit.ghidra.Utils.addRowToDescriptor;

public class AutoAnalysisResultsTableModel extends ThreadedTableModelStub<GhidraFunctionMatchWithSignature> implements ProgramTableModel {
	private static final long serialVersionUID = -8437395899512765590L;
	private Program program;
	private PluginTool tool;
	private boolean allowReload = false;
	private double confidenceThreshold;
	private List<Collection> collections;
	private boolean onlyNamed;
	private boolean fetchSignatures;


	public AutoAnalysisResultsTableModel(PluginTool plugin) {
		super("Collections Table Model", plugin);
		this.tool = plugin;
		this.program = null;
	}

	@Override
	protected void doLoad(Accumulator<GhidraFunctionMatchWithSignature> accumulator, TaskMonitor monitor)
			throws CancelledException {
		if (allowReload) {
			GhidraRevengService apiService = tool.getService(GhidraRevengService.class);
			ProgramManager programManager = tool.getService(ProgramManager.class);

			this.program = programManager.getCurrentProgram();
			Map<Function, List<GhidraFunctionMatch>> r = apiService.getSimilarFunctions(
					program,
					1,
					1 - confidenceThreshold,
					onlyNamed,
					collections
			);
				r.values().stream()
						.takeWhile(t -> !monitor.isCancelled())
						// Filter out functions that have no matches
						.filter(list -> !list.isEmpty())
						// Get the best match
						.map(List::getFirst)
						// Filter out matches that are below the threshold
						.filter(match -> match.confidence() >= confidenceThreshold)
						.map((match) -> {
									if (fetchSignatures) {
										return GhidraFunctionMatchWithSignature.createWith(match, apiService);
									} else {
										return new GhidraFunctionMatchWithSignature(match, null);
									}
								}
						)
						// Add the best matches to the table
						.forEachOrdered(accumulator::add);

			// Block automatic reloads again until the user explicitly triggers it
			allowReload = false;
		}
		return;
	}

	@Override
	public void clearData() {
		super.clearData();
	}

	@Override
	protected TableColumnDescriptor<GhidraFunctionMatchWithSignature> createTableColumnDescriptor() {
		TableColumnDescriptor<GhidraFunctionMatchWithSignature> descriptor = new TableColumnDescriptor<GhidraFunctionMatchWithSignature>();
		addRowToDescriptor(descriptor, "Destination Symbol", Function.class, GhidraFunctionMatchWithSignature::function);

		addRowToDescriptor(descriptor, "Destination Symbol SourceType", false, SourceType.class,
				(rowObject) -> rowObject.function().getSymbol().getSource()
		);

		addRowToDescriptor(descriptor, "Destination Address", false, Address.class,
				(rowObject -> rowObject.function().getEntryPoint())
		);

		addRowToDescriptor(descriptor, "Called Functions", false, Integer.class,
				(rowObject -> rowObject.function().getCalledFunctions(null).size())
		);

		addRowToDescriptor(descriptor, "Destination Function Size", false, Long.class,
				(row) -> row.function().getBody().getNumAddresses());

		addRowToDescriptor(descriptor, "Source Symbol", String.class, (row) -> row.functionMatch().nearest_neighbor_function_name());

		addRowToDescriptor(descriptor, "Signature", String.class, (row) -> row.signature().map(sig -> sig.func_types().getSignature()).orElse(null));

		addRowToDescriptor(descriptor, "Source Binary", String.class, (row) -> row.functionMatch().nearest_neighbor_binary_name());

		addRowToDescriptor(descriptor, "Confidence", Double.class, (row) -> row.functionMatch().confidence());

		return descriptor;
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
		return this.program;
	}


	public void enableLoad() {
		allowReload = true;
	}

	public void setConfidenceThreshold(double v) {
		this.confidenceThreshold = v;
	}

	public void setCollections(List<Collection> collections) {
		this.collections = collections;
	}

	public void setOnlyShowNamed(boolean selected) {
		this.onlyNamed = selected;
	}

	public void setFetchSignatures(boolean selected) {
		this.fetchSignatures = selected;
	}
}
