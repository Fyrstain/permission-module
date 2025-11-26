package com.fyrstain.fhir.security.core.model;

import org.hl7.fhir.instance.model.api.IBaseResource;

public class FhirResponse {
    private int statusCode;
    private IBaseResource resource; // Could be a Bundle or a single resource

    public int getStatusCode() {
        return statusCode;
    }

    public FhirResponse setStatusCode(int statusCode) {
        this.statusCode = statusCode;
        return this;
    }

    public IBaseResource getResource() {
        return resource;
    }

    public FhirResponse setResource(IBaseResource resource) {
        this.resource = resource;
        return this;
    }
}
