package com.fyrstain.fhir.security.core;

import com.fyrstain.fhir.security.core.model.FhirResponse;
import com.fyrstain.fhir.security.core.model.PermissionOperation;
import com.fyrstain.fhir.security.core.model.PermissionRule;
import org.hl7.fhir.instance.model.api.IBaseResource;

import java.util.List;
import java.util.Map;

public interface PermissionEvaluator {
    List<PermissionRule> compileRules(List<IBaseResource> permissionResources);
    boolean canPerform(String resourceType, PermissionOperation operation, List<PermissionRule> rules);
    Map<String, List<String>> updateSearchParameters(Map<String, List<String>>searchParameters, List<PermissionRule> rules);
    FhirResponse filterResponse(FhirResponse response, List<PermissionRule> rules);
}
