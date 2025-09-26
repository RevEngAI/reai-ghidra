package ai.reveng.toolkit.ghidra.core.services.logging;

import ghidra.framework.plugintool.ServiceInfo;

@ServiceInfo(description = "Service for writing plugin messages to a logfile that can then be exported by a user for debuging")
public interface ReaiLoggingService {
	public void info(String message);
	public void warn(String message);
	public void error(String message);
	public void export(String targetDirectoryPath, String exportedFileName);
}
