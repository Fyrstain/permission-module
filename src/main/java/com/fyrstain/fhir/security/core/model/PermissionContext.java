package com.fyrstain.fhir.security.core.model;

import java.util.Collections;
import java.util.Set;

public class PermissionContext {

    private final String userId;         // stable identifier (e.g., Practitioner/123 or username)
    private final String displayName;    // optional — for logging/debugging
    private final String token;          // raw JWT or access token if needed for introspection
    private final Set<String> roles;     // optional — pre-extracted from token (Keycloak roles/scopes)
    private final String organizationId; // optional — useful if org-level permissions exist

    public PermissionContext(
            String userId,
            String displayName,
            String token,
            Set<String> roles,
            String organizationId
    ) {
        this.userId = userId;
        this.displayName = displayName;
        this.token = token;
        this.roles = roles != null ? roles : Collections.emptySet();
        this.organizationId = organizationId;
    }

    public String getUserId() {
        return userId;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getToken() {
        return token;
    }

    public Set<String> getRoles() {
        return roles;
    }

    public String getOrganizationId() {
        return organizationId;
    }
}
