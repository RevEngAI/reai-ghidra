package ai.reveng.toolkit.ghidra.task;

import java.io.File;

import com.moandjiezana.toml.Toml;

import ai.reveng.toolkit.RE_AIConfig;
import ai.reveng.toolkit.exceptions.RE_AIConfigException;
import ai.reveng.toolkit.ghidra.RE_AIToolkitHelper;
import ai.reveng.toolkit.model.ModelInfo;
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
			callback.onTaskError(new RE_AIConfigException("No Config File "));
			return;
		}

		RE_AIConfig conf = null;
		try {
			conf = RE_AIToolkitHelper.getInstance().getClient().getConfig();
		} catch (NullPointerException e) {
			System.err.println("No Config file set");
			callback.onTaskError(new RE_AIConfigException("No Config File "));
			return;
		}

		Toml toml = new Toml().read(configFile);
		conf.setApiKey(toml.getString("apikey"));
		conf.setHost(toml.getString("host"));
		conf.setModel(new ModelInfo(toml.getString("model")));

		System.out.format("Set conf to: %s, %s, %s", toml.getString("apikey"), toml.getString("host"),
				toml.getString("model"));

		callback.onTaskCompleted(true);
	}

}
