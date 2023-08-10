package ai.reveng.reait.ghidra;

import ai.reveng.reait.client.Client;
import ghidra.program.flatapi.FlatProgramAPI;

public final class REAITHelper {
	private static REAITHelper instance;
	
	private Client client;
	private FlatProgramAPI flatAPI;
	
	private REAITHelper() {
		return;
	}
	
	public static REAITHelper getInstance() {
		if (instance == null) {
			instance = new REAITHelper();
		}
		
		return instance;
	}

	public Client getClient() {
		return client;
	}

	public void setClient(Client client) {
		this.client = client;
	}

	public FlatProgramAPI getFlatAPI() {
		return flatAPI;
	}

	public void setFlatAPI(FlatProgramAPI flatAPI) {
		this.flatAPI = flatAPI;
	}
}
