package ai.reveng.toolkit.ghidra.core.services.configuration;

public interface ConfigurationService {
	public String getApiKey();
	public void setApiKey(String apiKey);
	
	public String getHostname();
	public void setHostname(String hostname);
	
	public String getModel();
	public void setModel(String model);
}
