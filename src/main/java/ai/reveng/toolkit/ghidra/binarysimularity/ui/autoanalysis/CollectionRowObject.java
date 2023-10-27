package ai.reveng.toolkit.ghidra.binarysimularity.ui.autoanalysis;

public class CollectionRowObject {
	private final String collectionName;
	private boolean include;
	
	public CollectionRowObject(String collectionName, boolean include) {
		this.collectionName = collectionName;
		this.include = include;
	}
	
	public String getCollectionName() {
		return collectionName;
	}

	public boolean isInclude() {
		return include;
	}
	
	public void setInclude(boolean isInclude) {
		this.include = isInclude;
	}
}
