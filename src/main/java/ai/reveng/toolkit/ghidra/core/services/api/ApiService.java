package ai.reveng.toolkit.ghidra.core.services.api;

import java.nio.file.Path;
import java.util.List;

public interface ApiService {
	public ApiResponse echo();
	
	public ApiResponse analyse(Path binPath, String modelName, int baseAddr, AnalysisOptions opts);
	public ApiResponse analyse(Path binPath, int baseAddr, AnalysisOptions opts);
	
	public ApiResponse status(String binHash);
	
	public ApiResponse delete(String binHash, String modelName);
	public ApiResponse delete(String binHash);
	
	public ApiResponse embeddings(String binHash, String modelName);
	public ApiResponse embeddings(String binHash);
	
	public ApiResponse signature(String binHash, String modelName);
	public ApiResponse signature(String binHash);
	
	public ApiResponse logs(String binHash, String modelName);
	public ApiResponse logs(String binHash);
	
	public ApiResponse cves(String binHash, String modelName);
	public ApiResponse cves(String binHash);
	
	public ApiResponse nearestSymbols(List<Double> embedding, String modelName, int nns, String[] collections);
	public ApiResponse nearestSymbols(List<Double> embedding, int nns, String[] collections);
	
	public ApiResponse nearestBinaries(List<Double> embedding, int nns, String[] collections);
	public ApiResponse nearestBinaries(List<Double> embedding, String modelName, int nns, String[] collections);
	
	public ApiResponse sbom(String binHash, String modelName);
	public ApiResponse sbom(String binHash);
	
	public ApiResponse models();
	
	public ApiResponse explain(String decompiledFunction);
}
