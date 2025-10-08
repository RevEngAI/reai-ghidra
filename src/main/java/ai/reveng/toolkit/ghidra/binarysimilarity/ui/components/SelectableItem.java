package ai.reveng.toolkit.ghidra.binarysimilarity.ui.components;

import java.util.Objects;

/**
 * Represents an item that can be selected in the UI with both an ID and display name.
 * The ID is used for API calls while the name is displayed to the user.
 */
public class SelectableItem {
    private final Integer id;
    private final String name;

    public SelectableItem(Integer id, String name) {
        this.id = id;
        this.name = name;
    }

    public Integer getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SelectableItem that = (SelectableItem) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public String toString() {
        return name; // Display name to user
    }
}
