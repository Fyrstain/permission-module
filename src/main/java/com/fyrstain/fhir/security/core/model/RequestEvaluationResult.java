package com.fyrstain.fhir.security.core.model;

import java.util.Collections;
import java.util.List;
import java.util.Map;

public class RequestEvaluationResult {

    private final boolean allowed;
    private final Map<String, List<String>> modifiedSearchParameters;
    private final List<PermissionRule> rulesApplied;
    private final List<String> warnings;

    public RequestEvaluationResult(boolean allowed,
                                   Map<String, List<String>> modifiedSearchParameters,
                                   List<PermissionRule> rulesApplied,
                                   List<String> warnings) {
        this.allowed = allowed;
        this.modifiedSearchParameters = modifiedSearchParameters;
        this.rulesApplied = rulesApplied;
        this.warnings = warnings != null ? warnings : Collections.emptyList();
    }

    public boolean isAllowed() {
        return allowed;
    }

    public Map<String, List<String>> getModifiedSearchParameters() {
        return modifiedSearchParameters;
    }

    public List<PermissionRule> getRulesApplied() {
        return rulesApplied;
    }

    public List<String> getWarnings() {
        return warnings;
    }
}
