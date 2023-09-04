package ai.reveng.toolkit.ghidra.core.services.api;

import java.util.HashMap;
import java.util.Map;

/**
 * Models optional params to the API that we can infer
 */
public class AnalysisOptions {
	private String fileOptions;
	private String isaOptions;
	private String platformOptions;
	private boolean dynamicExecution;
	private String commandLineArgs;
	
	private AnalysisOptions(Builder builder) {
		this.fileOptions = builder.fileOptions;
		this.isaOptions = builder.isaOptions;
		this.platformOptions = builder.platformOptions;
		this.dynamicExecution = builder.dynamicExecution;
		this.commandLineArgs = builder.commandLineArgs;
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
	
	public static class Builder {
		private String fileOptions = "Auto";
		private String isaOptions = "Auto";
		private String platformOptions = "Auto";
		private boolean dynamicExecution = false;
		private String commandLineArgs = "";
		
		public Builder fileOptions(String fileOptions) {
			this.fileOptions = fileOptions;
			return this;
		}
		
		public Builder isaOptions(String isaOptions) {
			this.isaOptions = isaOptions;
			return this;
		}
		
		public Builder platformOptions(String platformOptions) {
			this.platformOptions = platformOptions;
			return this;
		}
		
		public Builder dynamicExecution(boolean dynamicExecution) {
			this.dynamicExecution = dynamicExecution;
			return this;
		}
		
		public Builder commandLineArguments(String commandLineArguments) {
			this.commandLineArgs = commandLineArguments;
			return this;
		}
		
		public AnalysisOptions build() {
			return new AnalysisOptions(this);
		}
	}
}
