package ai.reveng.toolkit.ghidra.core.services.api;

import java.nio.file.Path;
import java.util.List;

import org.json.JSONObject;

import ai.reveng.toolkit.ghidra.core.CorePlugin;
import ghidra.framework.plugintool.ServiceInfo;

@ServiceInfo(defaultProvider = CorePlugin.class, description = "Interact with RevEngAi API")
public interface ApiService {
	public ApiResponse echo();
	
	public ApiResponse upload(Path binPath);
	
	public ApiResponse analyse(AnalysisOptions opts);
	
	public ApiResponse status(long binID);
	
	public ApiResponse delete(long binID, String modelName);
	public ApiResponse delete(long binID);
	
	public ApiResponse embeddings(long binID, String modelName);
	public ApiResponse embeddings(long binID);
	
	public ApiResponse signature(long binID, String modelName);
	public ApiResponse signature(long binID);
	
	public ApiResponse logs(long binID, String modelName);
	public ApiResponse logs(long binID);
	
	public ApiResponse cves(long binID, String modelName);
	public ApiResponse cves(long binID);
	
	// leave alone
	public ApiResponse nearestSymbols(List<Double> embedding, String ignoreHash, String modelName, int nns, String collections);
	public ApiResponse nearestSymbols(List<Double> embedding, String ignoreHash, int nns, String collections);
	
	// leave alone
	public ApiResponse nearestBinaries(List<Double> embedding, int nns, String collections);
	public ApiResponse nearestBinaries(List<Double> embedding, String modelName, int nns, String collections);
	
	public ApiResponse sbom(long binID, String modelName);
	public ApiResponse sbom(long binID);
	
	public ApiResponse models();
	
	public ApiResponse collections();
	
	public ApiResponse explain(String decompiledFunction);
}
