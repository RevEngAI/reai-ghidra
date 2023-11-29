package ai.reveng.toolkit.ghidra.core.services.api;

import java.util.HashMap;
import java.util.Map;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Models optional params to the API that we can infer
 */
public class AnalysisOptions {
	private String binaryScope;
	private String commandLineArgs;
	private boolean dynamicExecution;
	private String fileName;
	private String fileOptions;
	private String isaOptions;
	private String modelName;
	private String platformOptions;
	private int priority;
	private String binHash;
	private JSONObject symbols;
	private String[] tags;
	
	private AnalysisOptions(Builder builder) {
		this.binaryScope = builder.binaryScope;
		this.commandLineArgs = builder.commandLineArgs;
		this.dynamicExecution = builder.dynamicExecution;
		this.fileName = builder.fileName;
		this.fileOptions = builder.fileOptions;
		this.isaOptions = builder.isaOptions;
		this.modelName = builder.modelName;
		this.platformOptions = builder.platformOptions;
		this.priority = builder.priority;
		this.binHash = builder.binHash;
		this.symbols = builder.symbols;
		this.tags = builder.tags;
		
	}
	
	public Map<String, String> toMap() {
		Map<String, String> params = new HashMap<>();
		params.put("file_options", fileOptions);
		params.put("isa_options", isaOptions);
		params.put("platform_options", platformOptions);
		params.put("dynamic_execution", Boolean.toString(dynamicExecution));
		params.put("command_line_args", commandLineArgs);
		return params;
	}
	
	public JSONObject toJSON() {
		JSONObject analysisConfig = new JSONObject();
		analysisConfig.put("binary_scope", binaryScope);
		analysisConfig.put("command_line_args", commandLineArgs);
		analysisConfig.put("dynamic_execution", dynamicExecution);
		analysisConfig.put("file_name", fileName);
		analysisConfig.put("file_options", fileOptions);
		analysisConfig.put("isa_options", isaOptions);
		analysisConfig.put("model_name", modelName);
		analysisConfig.put("platform_options", platformOptions);
		analysisConfig.put("priority", priority);
		analysisConfig.put("sha_256_hash", binHash);
		analysisConfig.put("symbols", symbols);
		
		JSONArray jTags = new JSONArray();
		for (String tag : tags) {
			jTags.put(tag);
		}
		analysisConfig.put("tags", jTags);
		return analysisConfig;
	}
	
	public static class Builder {
		private String binaryScope = "PRIVATE";
		private String commandLineArgs = "";
		private boolean dynamicExecution = false;
		private String fileName = "";
		private String fileOptions = "Auto";
		private String isaOptions = "Auto";
		private String modelName = "binnet-0.1";
		private String platformOptions = "Auto";
		private int priority = 10; // plugin has priority by default
		private String binHash = "";
		private JSONObject symbols = null;
		private String[] tags = {};
		
		
		public Builder binaryScope(String binaryScope) {
			this.binaryScope = binaryScope;
			return this;
		}
		
		public Builder commandLineArguments(String commandLineArguments) {
			this.commandLineArgs = commandLineArguments;
			return this;
		}
		
		public Builder dynamicExecution(boolean dynamicExecution) {
			this.dynamicExecution = dynamicExecution;
			return this;
		}
		
		public Builder fileName(String fileName) {
			this.fileName = fileName;
			return this;
		}
		
		public Builder fileOptions(String fileOptions) {
			this.fileOptions = fileOptions;
			return this;
		}
		
		public Builder isaOptions(String isaOptions) {
			this.isaOptions = isaOptions;
			return this;
		}
		
		public Builder modelName(String modelName) {
			this.modelName = modelName;
			return this;
		}
		
		public Builder platformOptions(String platformOptions) {
			this.platformOptions = platformOptions;
			return this;
		}
		
		public Builder priority(int priority) {
			this.priority = priority;
			return this;
		}

		public Builder binHash(String binHash) {
			this.binHash = binHash;
			return this;
		}

		public Builder symbols(JSONObject symbols) {
			this.symbols = symbols;
			return this;
		}

		public Builder tags(String[] tags) {
			this.tags = tags;
			return this;
		}
		
		public AnalysisOptions build() {
			return new AnalysisOptions(this);
		}
	}
}
