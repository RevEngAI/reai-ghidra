package ai.reveng.toolkit.ghidra.core.services.api.types;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.json.JSONArray;

public class Binary {
	private final Map<Long, FunctionEmbedding> functionEmbeddings;

	private final List<Double> binaryEmbedding;
	
	public Binary(JSONArray jBinaryEmbeddings) {
		functionEmbeddings = new HashMap<Long, FunctionEmbedding>();
		binaryEmbedding = new ArrayList<>();
		
		for (int i = 0; i < jBinaryEmbeddings.length(); i++) {
			FunctionEmbedding tmp = new FunctionEmbedding(jBinaryEmbeddings.getJSONObject(i));
			functionEmbeddings.put(tmp.getVaddr(), tmp);
		}
	}
	
	public List<Double> getEmbedding() {
		List<Double> embedding = new ArrayList<>();
		
		for (FunctionEmbedding fe : functionEmbeddings.values())
			embedding.addAll(fe.getEmbedding());
			
		return embedding;
	}
	
	public Map<Long, FunctionEmbedding> getFunctionEmbeddings() {
		return functionEmbeddings;
	}
	
	public FunctionEmbedding getFunctionEmbedding(long fAddr) {
		return functionEmbeddings.containsKey(fAddr) ? functionEmbeddings.get(fAddr) : null;
	}
}
