package com.fyrstain.fhir.security.core.model;

import org.hl7.fhir.instance.model.api.IBaseResource;

import java.util.List;
import java.util.Map;

public class FhirRequest {

    private HTTPVerb method;
    private String resourceType;
    private String resourceId;
    private String operationName;
    private Map<String, List<String>> searchParameters;

    private IBaseResource body; // optional (for create/update)

    public PermissionOperation getOperation() {
        switch (method) {
            case GET:
                if (resourceId != null) {
                    return PermissionOperation.READ;
                }
                return PermissionOperation.SEARCH;
            case POST:
                if (operationName != null) {
                    return PermissionOperation.CUSTOM;
                }
                return PermissionOperation.CREATE;
            case PUT:
                return PermissionOperation.UPDATE;
            case PATCH:
                return  PermissionOperation.PATCH;
            case DELETE:
                return PermissionOperation.DELETE;
            default:
                throw new IllegalArgumentException("Unknown method: " + method);
        }
    }

    public HTTPVerb getMethod() {
        return method;
    }

    public FhirRequest setMethod(HTTPVerb method) {
        this.method = method;
        return this;
    }

    public String getResourceType() {
        return resourceType;
    }

    public FhirRequest setResourceType(String resourceType) {
        this.resourceType = resourceType;
        return this;
    }

    public String getResourceId() {
        return resourceId;
    }

    public FhirRequest setResourceId(String resourceId) {
        this.resourceId = resourceId;
        return this;
    }

    public Map<String, List<String>> getSearchParameters() {
        return searchParameters;
    }

    public FhirRequest setSearchParameters(Map<String, List<String>> searchParameters) {
        this.searchParameters = searchParameters;
        return this;
    }

    public String getOperationName() {
        return operationName;
    }

    public FhirRequest setOperationName(String operationName) {
        this.operationName = operationName;
        return this;
    }

    public IBaseResource getBody() {
        return body;
    }

    public FhirRequest setBody(IBaseResource body) {
        this.body = body;
        return this;
    }

    public enum HTTPVerb {
        GET, POST, PUT, DELETE, PATCH
    }
}
