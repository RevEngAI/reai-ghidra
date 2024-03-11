package ai.reveng.toolkit.ghidra.core.models;

public class ReaiConfig {
	private PluginSettings pluginSettings;
	
	public PluginSettings getPluginSettings() {
		return pluginSettings;
	}

	public void setPluginSettings(PluginSettings pluginSettings) {
		this.pluginSettings = pluginSettings;
	}
	
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("REAI Config:\n");
		sb.append("\tPlugin Settings:\n");
		sb.append("\t\tAPI_Key: " + this.pluginSettings.getApiKey() + "\n");
		sb.append("\t\tHostname: " + this.pluginSettings.getHostname() + "\n");
		sb.append("\t\tModel Name: " + this.pluginSettings.getModelName() + "\n");
		return sb.toString();
	}
	
	public static class PluginSettings {
		private String apiKey;
		private String hostname;
		private String modelName;
		
		public String getApiKey() {
			return apiKey;
		}
		
		public void setApiKey(String apiKey) {
			this.apiKey = apiKey;
		}
		
		public String getHostname() {
			return hostname;
		}
		
		public void setHostname(String hostname) {
			this.hostname = hostname;
		}
		
		public String getModelName() {
			return modelName;
		}
		
		public void setModelName(String modelName) {
			this.modelName = modelName;
		}
	}
}
