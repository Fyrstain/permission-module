package com.fyrstain.fhir.security.core.r4;

import ca.uhn.fhir.context.FhirContext;
import ca.uhn.fhir.context.FhirVersionEnum;
import ca.uhn.fhir.context.RuntimeSearchParam;
import ca.uhn.fhir.rest.server.exceptions.ResourceNotFoundException;
import com.fyrstain.fhir.security.core.model.PermissionRule;
import org.hl7.fhir.instance.model.api.IBaseResource;
import org.hl7.fhir.r4.context.SimpleWorkerContext;
import org.hl7.fhir.r4.fhirpath.FHIRPathEngine;
import org.hl7.fhir.r4.model.Base;
import org.hl7.fhir.r4.model.Identifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Used to match single resources with permissions criteria if needed
 */
public class MatcherUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(MatcherUtils.class);

    private static final FhirContext CONTEXT = FhirContext.forCached(FhirVersionEnum.R4);
    private static final FHIRPathEngine FHIR_PATH_ENGINE;

    static {
        try {
            FHIR_PATH_ENGINE = new FHIRPathEngine(new SimpleWorkerContext());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void matchOrThrow(IBaseResource resource, List<PermissionRule> rules) {
        try {
            String resourceType = resource.fhirType();

            //TODO Improve rule selection here
            List<ParsedCriteria> criterion = rules.stream().filter(rule -> resourceType.equals(rule.getResourceType()))
                    .flatMap(r -> r.getSearchExpressions().stream())
                    .map(MatcherUtils::parseCriteria)
                    .collect(Collectors.toList());

            boolean match = criterion.stream().allMatch(criteria -> {
                RuntimeSearchParam searchParam = findSearchParam(resource, criteria.paramName);

                List<Base> results = evaluateFhirPath(resource, searchParam);

                return checkTokenMatch(results, criteria);
            });

            if (!match) {
                throw new ResourceNotFoundException("Could not find resource.");
            }
        } catch (IllegalArgumentException e) {
            //For now, we ignore unknown criteria, which means they won't filter the results.
            LOGGER.warn("Ignored resource matching", e);
        }
    }

    private static ParsedCriteria parseCriteria(String criteria) {
        // Expect format: "name=value"
        int idx = criteria.indexOf('=');
        if (idx < 0) {
            throw new IllegalArgumentException("Invalid criteria: " + criteria);
        }

        String param = criteria.substring(0, idx).trim();
        String value = criteria.substring(idx + 1).trim();

        // We're only supporting token-style for now: "system|value"
        String[] parts = value.split("\\|", -1); // keep empty final part

        if (parts.length != 2) {
            // For now we skip anything not in system|value format
            throw new IllegalArgumentException("Unsupported criteria format: " + criteria);
        }

        return new ParsedCriteria(param, parts[0], parts[1]);
    }

    private static RuntimeSearchParam findSearchParam(IBaseResource resource, String name) {
        RuntimeSearchParam searchParam = CONTEXT.getResourceDefinition(resource).getSearchParam(name);

        if (searchParam == null) {
            throw new IllegalArgumentException("Unknown search parameter: " + name);
        }

        return searchParam;
    }

    private static List<Base> evaluateFhirPath(IBaseResource resource, RuntimeSearchParam sp) {
        String expr = sp.getPath();
        if (expr == null || expr.isEmpty()) {
            throw new IllegalStateException("SearchParameter has no FHIRPath expression");
        }

        return FHIR_PATH_ENGINE.evaluate((Base) resource, expr);
    }

    private static boolean checkTokenMatch(List<Base> extracted, ParsedCriteria parsed) {
        // Expecting token-like objects: Identifier, Coding, CodeableConcept, etc.
        for (Base base : extracted) {
            if (base instanceof Identifier id) {
                boolean systemMatches = parsed.system.isEmpty() ||
                        parsed.system.equals(id.getSystem());
                boolean valueMatches = parsed.value.isEmpty() ||
                        parsed.value.equals(id.getValue());
                if (systemMatches && valueMatches) return true;
            }
            //Else ignored for now
        }
        return false;
    }

    private record ParsedCriteria(String paramName, String system, String value) {}
}
