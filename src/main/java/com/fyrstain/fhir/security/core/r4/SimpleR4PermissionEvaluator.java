package com.fyrstain.fhir.security.core.r4;

import com.fyrstain.fhir.security.core.SimplePermissionEvaluator;
import com.fyrstain.fhir.security.core.model.FhirResponse;
import com.fyrstain.fhir.security.core.model.PermissionRule;

import java.util.List;
import java.util.stream.Collectors;

public class SimpleR4PermissionEvaluator extends SimplePermissionEvaluator {

    /**
     * {@inheritDoc}
     */
    @Override
    public FhirResponse filterResponse(FhirResponse response, List<PermissionRule> rules) {
        List<String> blacklistExpressions = rules.stream()
                .flatMap(r -> r.getBlacklistExpressions().stream()).collect(Collectors.toList());

        FilterUtils.removeFieldsByExpression(response.getResource(), blacklistExpressions);
        return response;
    }
}
