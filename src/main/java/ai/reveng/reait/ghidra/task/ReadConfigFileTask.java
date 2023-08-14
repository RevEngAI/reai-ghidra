package ai.reveng.reait.ghidra.task;

import java.io.File;

import com.moandjiezana.toml.Toml;

import ai.reveng.reait.REAITConfig;
import ai.reveng.reait.exceptions.REAIConfigException;
import ai.reveng.reait.ghidra.REAITHelper;
import ai.reveng.reait.model.ModelInfo;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class ReadConfigFileTask extends Task {
	private TaskCallback<Boolean> callback;

	public ReadConfigFileTask(TaskCallback<Boolean> callback) {
		super("Read Config File from Disk", true, false, false);
		this.callback = callback;
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		String path = System.getProperty("user.home") + File.separator + ".reaiconf.toml";
		File configFile = new File(path);
		
		if (!configFile.exists()) {
			System.out.println("Could not find config file");
			callback.onTaskError(new REAIConfigException("No Config File "));
			return;
		}
		
		REAITConfig conf = null;
		try {
			conf = REAITHelper.getInstance().getClient().getConfig();
		} catch (NullPointerException e) {
			System.err.println("No Config file set");
			callback.onTaskError(new REAIConfigException("No Config File "));
			return;
		}
		
		Toml toml = new Toml().read(configFile);
		conf.setApiKey(toml.getString("apikey"));
		conf.setHost(toml.getString("host"));
		conf.setModel(new ModelInfo(toml.getString("model")));
		
		System.out.format("Set conf to: %s, %s, %s", toml.getString("apikey"), toml.getString("host"), toml.getString("model"));
		
		callback.onTaskCompleted(true);
	}

}
