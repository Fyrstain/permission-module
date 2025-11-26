package com.fyrstain.fhir.security.core;

import com.fyrstain.fhir.security.core.model.PermissionContext;
import org.hl7.fhir.instance.model.api.IBaseResource;

import java.util.ArrayList;
import java.util.List;

public class MockPermissionService implements PermissionService {

    private List<IBaseResource> rules = new ArrayList<>();

    public void addRule(IBaseResource rule) {
        rules.add(rule);
    }

    public void flushRules() {
        rules = new ArrayList<>();
    }

    @Override
    public List<IBaseResource> getPermissions(PermissionContext context) {
        return rules;
    }
}