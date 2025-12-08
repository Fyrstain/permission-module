package com.fyrstain.fhir.security.core;

import com.fyrstain.fhir.security.core.model.FhirResponse;
import com.fyrstain.fhir.security.core.model.PermissionOperation;
import com.fyrstain.fhir.security.core.model.PermissionRule;
import org.hl7.fhir.r5.model.Permission;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.fyrstain.fhir.security.core.PermissionHelper.buildPermission;
import static org.junit.jupiter.api.Assertions.*;

public class UpdateSearchParametersTest {

    private final PermissionEvaluator evaluator = new SimplePermissionEvaluator() {
        @Override
        public FhirResponse filterResponse(FhirResponse response, List<PermissionRule> rules) {
            return null;
        }
    };

    @Test
    void updateSearchParameters_oneExpression() {
        Map<String, List<String>> searchParameters = new HashMap<>();

        List<PermissionRule> rules = List.of(
                new PermissionRule("Patient", null, true,
        null, List.of("identifier=system|code&name=Toto"))
        );

        Map<String, List<String>> updatedSearchParameters = evaluator.updateSearchParameters("Patient", searchParameters, rules);

        assertNotNull(updatedSearchParameters);
        assertEquals(2, updatedSearchParameters.size());
        assertEquals(List.of("system|code"), updatedSearchParameters.get("identifier"));
        assertEquals(List.of("Toto"), updatedSearchParameters.get("name"));
    }

    @Test
    void updateSearchParameters_twoExpressions() {
        Map<String, List<String>> searchParameters = new HashMap<>();

        List<PermissionRule> rules = List.of(
                new PermissionRule("Patient", null, true,
                        null, List.of("identifier=system|code", "name=Toto"))
        );

        Map<String, List<String>> updatedSearchParameters = evaluator.updateSearchParameters("Patient", searchParameters, rules);

        assertNotNull(updatedSearchParameters);
        assertEquals(2, updatedSearchParameters.size());
        assertEquals(List.of("system|code"), updatedSearchParameters.get("identifier"));
        assertEquals(List.of("Toto"), updatedSearchParameters.get("name"));
    }

    @Test
    void updateSearchParameters_twoRules() {
        Map<String, List<String>> searchParameters = new HashMap<>();

        List<PermissionRule> rules = List.of(
                new PermissionRule("Patient", null, true,
                        null, List.of("identifier=system|code")),
                new PermissionRule("Patient", null, true,
                        null, List.of("name=Toto"))
        );

        Map<String, List<String>> updatedSearchParameters = evaluator.updateSearchParameters("Patient", searchParameters, rules);

        assertNotNull(updatedSearchParameters);
        assertEquals(2, updatedSearchParameters.size());
        assertEquals(List.of("system|code"), updatedSearchParameters.get("identifier"));
        assertEquals(List.of("Toto"), updatedSearchParameters.get("name"));
    }

    @Test
    void updateSearchParameters_twoSameSP() {
        Map<String, List<String>> searchParameters = new HashMap<>();

        List<PermissionRule> rules = List.of(
                new PermissionRule("Patient", null, true,
                        null, List.of("identifier=system|code")),
                new PermissionRule("Patient", null, true,
                        null, List.of("identifier=system2|code2"))
        );

        Map<String, List<String>> updatedSearchParameters = evaluator.updateSearchParameters("Patient", searchParameters, rules);

        assertNotNull(updatedSearchParameters);
        assertEquals(1, updatedSearchParameters.size());
        assertEquals(List.of("system|code", "system2|code2"), updatedSearchParameters.get("identifier"));
    }

    @Test
    void updateSearchParameters_comaExpression() {
        Map<String, List<String>> searchParameters = new HashMap<>();

        List<PermissionRule> rules = List.of(
                new PermissionRule("Patient", null, true,
                        null, List.of("identifier=system|code&name=Toto,Tata,Tutu"))
        );

        Map<String, List<String>> updatedSearchParameters = evaluator.updateSearchParameters("Patient", searchParameters, rules);

        assertNotNull(updatedSearchParameters);
        assertEquals(2, updatedSearchParameters.size());
        assertEquals(List.of("system|code"), updatedSearchParameters.get("identifier"));
        assertEquals(List.of("Toto", "Tata", "Tutu"), updatedSearchParameters.get("name"));
    }
}
