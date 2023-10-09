package ai.reveng.toolkit.ghidra.core.services.api.types;

import java.util.ArrayList;
import java.util.List;

import org.json.JSONArray;
import org.json.JSONObject;

public class FunctionEmbedding {
	private final String name;
	private final long vaddr;
	private final int size;
	private final List<Double> embedding;
	
	public FunctionEmbedding(JSONObject jFunctionEmbedding) {
		name = jFunctionEmbedding.getString("name");
		vaddr = jFunctionEmbedding.getLong("vaddr");
		size = jFunctionEmbedding.getInt("size");
		embedding = new ArrayList<>();
		
		JSONArray jEmbedding = jFunctionEmbedding.getJSONArray("embedding");
		for (int i = 0; i < jEmbedding.length(); i++) {
			embedding.add(jEmbedding.getDouble(i));
		}
	}

	public String getName() {
		return name;
	}

	public long getVaddr() {
		return vaddr;
	}

	public int getSize() {
		return size;
	}

	public List<Double> getEmbedding() {
		return embedding;
	}
}
