package ai.reveng.toolkit.ghidra.core.services.api.types;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.json.JSONArray;

import ghidra.program.model.address.Address;

public class Binary {
	private final Map<String, FunctionEmbedding> functionEmbeddings;

	private final List<Double> binaryEmbedding;
	
	public Binary(JSONArray jBinaryEmbeddings, Address baseAddr) {
		functionEmbeddings = new HashMap<String, FunctionEmbedding>();
		binaryEmbedding = new ArrayList<>();
		
		for (int i = 0; i < jBinaryEmbeddings.length(); i++) {
			FunctionEmbedding tmp = new FunctionEmbedding(jBinaryEmbeddings.getJSONObject(i));
			Address tmpAddr = baseAddr.add(tmp.getVaddr());
			System.out.println("Base Addr: " + baseAddr.toString() + " offset: " + tmp.getVaddr() + " = " + tmpAddr.toString());
			functionEmbeddings.put(tmpAddr.toString(), tmp);
		}
	}
	
	public List<Double> getEmbedding() {
		List<Double> embedding = new ArrayList<>();
		
		for (FunctionEmbedding fe : functionEmbeddings.values())
			embedding.addAll(fe.getEmbedding());
			
		return embedding;
	}
	
	public Map<String, FunctionEmbedding> getFunctionEmbeddings() {
		return functionEmbeddings;
	}
	
	public FunctionEmbedding getFunctionEmbedding(String fAddr) {
		return functionEmbeddings.containsKey(fAddr) ? functionEmbeddings.get(fAddr) : null;
	}
	
	public String toString() {
		return functionEmbeddings.keySet().toString();
	}
}
