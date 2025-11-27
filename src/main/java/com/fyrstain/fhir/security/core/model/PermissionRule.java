package com.fyrstain.fhir.security.core.model;

import java.util.EnumSet;
import java.util.List;
import java.util.stream.Collectors;

//TODO See if we only want one big structure that checks all permissions ?
public class PermissionRule {

    private final String resourceType;
    private final EnumSet<PermissionOperation> operations; // e.g. READ, UPDATE, DELETE, CREATE
    private final boolean allow; // true = allow, false = deny (if you plan to support deny rules later)

    private final List<String> searchExpressions;
    private final List<String> blacklistExpressions;


    public PermissionRule(String resourceType, EnumSet<PermissionOperation> operations, boolean allow,
                          List<String> blacklistExpressions, List<String> searchExpressions) {
        this.resourceType = resourceType;
        this.operations = operations;
        this.allow = allow;
        this.blacklistExpressions = blacklistExpressions;
        this.searchExpressions = searchExpressions;
    }

    public boolean allows(String resourceType, PermissionOperation op) {
        return allow && (this.resourceType.equals("*") || this.resourceType.equals(resourceType))
                && operations.contains(op);
    }

    public boolean denies(String resourceType, PermissionOperation op) {
        return !allow && (this.resourceType.equals("*") || this.resourceType.equals(resourceType))
                && operations.contains(op);
    }

    public List<String> getBlacklistExpressions() {
        return blacklistExpressions;
    }

    public List<String> getSearchExpressions() {
        return searchExpressions;
    }

    public boolean hasSearchExpressions() {
        return searchExpressions != null && !searchExpressions.isEmpty();
    }

    public String getResourceType() {
        return resourceType;
    }

    public EnumSet<PermissionOperation> getOperations() {
        return operations;
    }

    public boolean isAllow() {
        return allow;
    }

    @Override
    public String toString() {
        return "PermissionRule{\n" +
                "resourceType='" + resourceType + "\'\n" +
                ", operations=" + operations + '\n' +
                ", allow=" + allow + '\n' +
                ", blacklistExpressions=" + blacklistExpressions.stream().collect(Collectors.joining(", ")) + '\n' +
                '}';
    }
}
