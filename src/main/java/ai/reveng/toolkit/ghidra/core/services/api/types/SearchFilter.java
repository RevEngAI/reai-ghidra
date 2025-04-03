package ai.reveng.toolkit.ghidra.core.services.api.types;

/**
 * Special filters for the collection search endpoint
 * https://api.reveng.ai/v2/docs#tag/Collections/operation/list_collections_v2_collections_get
 */
public enum SearchFilter {
    official_only,
    user_only,
    team_only,
    public_only,
    hide_empty
}
