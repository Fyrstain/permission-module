package com.fyrstain.fhir.security.core;

import com.fyrstain.fhir.security.core.model.FhirResponse;
import com.fyrstain.fhir.security.core.model.PermissionOperation;
import com.fyrstain.fhir.security.core.model.PermissionRule;
import org.hl7.fhir.r5.model.Enumerations;
import org.hl7.fhir.r5.model.Permission;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.stream.Collectors;

import static com.fyrstain.fhir.security.core.PermissionHelper.*;
import static org.junit.jupiter.api.Assertions.*;

class PermissionCompilerTest {

    private final PermissionEvaluator evaluator = new SimplePermissionEvaluator() {
        @Override
        public FhirResponse filterResponse(FhirResponse response, List<PermissionRule> rules) {
            return null;
        }
    };

    @Test
    void compileRules_shouldIgnoreInactivePermissions() {
        Permission inactive = buildPermission(false);

        List<PermissionRule> rules = evaluator.compileRules(List.of(inactive));

        assertTrue(rules.isEmpty(), "Inactive permission must be ignored");
    }

    @Test
    void compileRules_shouldProduceAllowRuleWithoutExpressions() {
        Permission p = buildPermission(true);
        Permission.RuleComponent rule = newRule(true);

        // add activity: read + search
        rule.addActivity(activity("read", "search"));

        // no deny expressions because allow = true
        rule.addData(dataForInstance("Patient", null, null));

        p.addRule(rule);

        List<PermissionRule> rules = evaluator.compileRules(List.of(p));

        assertEquals(1, rules.size());

        PermissionRule producedRule = rules.get(0);
        assertEquals("Patient", producedRule.getResourceType());
        assertTrue(producedRule.isAllow());
        assertTrue(producedRule.getBlacklistExpressions().isEmpty());
        assertTrue(producedRule.getOperations().contains(PermissionOperation.READ));
        assertTrue(producedRule.getOperations().contains(PermissionOperation.SEARCH));
    }

    @Test
    void compileRules_shouldProduceDenyRuleWithExpressions() {
        Permission p = buildPermission(true);
        Permission.RuleComponent rule = newRule(false);

        rule.addActivity(activity("read"));
        rule.addData(dataForInstance("Observation", "value.where(code = 'secret')", null));

        p.addRule(rule);

        List<PermissionRule> rules = evaluator.compileRules(List.of(p));

        assertEquals(1, rules.size());

        PermissionRule producedRule = rules.get(0);

        assertEquals("Observation", producedRule.getResourceType());
        assertFalse(producedRule.isAllow());
        assertEquals(1, producedRule.getBlacklistExpressions().size());
        assertEquals("value.where(code = 'secret')", producedRule.getBlacklistExpressions().get(0));
    }

    @Test
    void compileRules_shouldSkipNonInstanceMeaning() {
        Permission p = buildPermission(true);
        Permission.RuleComponent rule = newRule(false);
        rule.addActivity(activity("read"));

        Permission.RuleDataComponent data = new Permission.RuleDataComponent();
        Permission.RuleDataResourceComponent res = data.getResourceFirstRep();

        // NON instance meaning
        res.setMeaning(Enumerations.ConsentDataMeaning.RELATED);
        res.getReference().setDisplay("Patient");

        rule.addData(data);
        p.addRule(rule);

        List<PermissionRule> rules = evaluator.compileRules(List.of(p));
        assertTrue(rules.isEmpty(), "Non-instance should be ignored");
    }

    @Test
    void compileRules_shouldCreateMultipleRules_ifMultipleTypesProvided() {
        Permission p = buildPermission(true);
        Permission.RuleComponent rule = newRule(false);
        rule.addActivity(activity("read"));

        rule.addData(dataForInstance("Patient", "name.given", null));
        rule.addData(dataForInstance("Encounter", "period.start", null));

        p.addRule(rule);

        List<PermissionRule> rules = evaluator.compileRules(List.of(p));

        assertEquals(2, rules.size());

        PermissionRule r1 = rules.get(0);
        PermissionRule r2 = rules.get(1);

        // Assert different resource types
        assertNotEquals(r1.getResourceType(), r2.getResourceType());
    }

    @Test
    void compileRules_shouldHandleMultiplePermissionResources() {
        // ---------- Permission 1 (ACTIVE, PERMIT) ----------
        Permission p1 = buildPermission(true);
        Permission.RuleComponent rule = newRule(true);
        rule.addActivity(activity("read"));

        rule.addData(dataForInstance("Patient", null, "identifier=system|"));
        p1.addRule(rule);

        // ---------- Permission 2 (ACTIVE, DENY with FHIRPath) ----------
        Permission p2 = buildPermission(true);
        Permission.RuleComponent rule2 = newRule(false);
        rule2.addActivity(activity("read"));

        rule2.addData(dataForInstance("Patient", "name.given", null));

        p2.addRule(rule2);

        // ---------- EXECUTE ----------
        List<PermissionRule> rules = evaluator.compileRules(List.of(p1, p2));

        // ---------- ASSERT ----------
        assertEquals(2, rules.size());

        PermissionRule allowRule = rules.stream().filter(PermissionRule::isAllow).findFirst().orElseThrow();
        PermissionRule denyRule = rules.stream().filter(r -> !r.isAllow()).findFirst().orElseThrow();

        // PERMIT rule
        assertEquals("Patient", allowRule.getResourceType());
        assertTrue(allowRule.getOperations().contains(PermissionOperation.READ));
        assertTrue(allowRule.getBlacklistExpressions().isEmpty()); // no expression for PERMIT
        assertEquals(1, allowRule.getSearchExpressions().size());
        assertTrue(allowRule.getSearchExpressions().contains("identifier=system|"));

        // DENY rule with FHIRPath
        assertEquals("Patient", denyRule.getResourceType());
        assertTrue(denyRule.getOperations().contains(PermissionOperation.READ));
        assertEquals(List.of("name.given"), denyRule.getBlacklistExpressions());
    }

    @Test
    void compileRules_shouldHandleMultiplePermissionResources2() {
        // ---------- Permission 1 (ACTIVE, PERMIT) ----------
        Permission p1 = buildPermission(true);
        Permission.RuleComponent rule = newRule(true);
        rule.addActivity(activity("read"));

        rule.addData(dataForInstance("Patient", null, "identifier=system|"));
        p1.addRule(rule);

        // ---------- Permission 2 (ACTIVE, DENY with FHIRPath) ----------
        Permission p2 = buildPermission(true);
        Permission.RuleComponent rule2 = newRule(true);
        rule2.addActivity(activity("read"));

        rule2.addData(dataForInstance("Patient", null, "active=true"));

        p2.addRule(rule2);

        // ---------- EXECUTE ----------
        List<PermissionRule> rules = evaluator.compileRules(List.of(p1, p2));

        // ---------- ASSERT ----------
        assertEquals(2, rules.size());

        List<PermissionRule> allowRule = rules.stream().filter(PermissionRule::isAllow).collect(Collectors.toList());
        assertTrue(rules.stream().allMatch(PermissionRule::isAllow));

        // PERMIT rule
        assertEquals(2, allowRule.size());
        assertTrue(allowRule.stream().allMatch(r -> "Patient".equals(r.getResourceType())));
        assertTrue(allowRule.stream().allMatch(r -> r.getOperations().contains(PermissionOperation.READ)));
        assertTrue(allowRule.stream().allMatch(r -> r.getBlacklistExpressions().isEmpty())); // no expression for PERMIT
        assertTrue(allowRule.get(0).getSearchExpressions().contains("identifier=system|"));
        assertTrue(allowRule.get(1).getSearchExpressions().contains("active=true"));
    }

    @Test
    void compileRules_shouldHandleOverlappingAllowAndDenyRules() {
        // -------- PERMIT rule --------
        Permission p1 = buildPermission(true);
        Permission.RuleComponent rule = newRule(true);
        rule.addActivity(activity("read"));

        rule.addData(dataForInstance("Observation", null, null));
        p1.addRule(rule);

        // -------- DENY rule --------
        Permission p2 = buildPermission(true);
        Permission.RuleComponent rule2 = newRule(false);
        rule2.addActivity(activity("read"));

        rule2.addData(dataForInstance("Observation", "value", null));

        p2.addRule(rule2);

        // -------- EXECUTE --------
        List<PermissionRule> rules = evaluator.compileRules(List.of(p1, p2));

        // -------- ASSERT --------
        assertEquals(2, rules.size());

        PermissionRule permit = rules.stream()
                .filter(PermissionRule::isAllow)
                .findFirst().orElseThrow();

        PermissionRule deny = rules.stream()
                .filter(r -> !r.isAllow())
                .findFirst().orElseThrow();

        // PERMIT
        assertEquals("Observation", permit.getResourceType());
        assertTrue(permit.getOperations().contains(PermissionOperation.READ));
        assertTrue(permit.getBlacklistExpressions().isEmpty());

        // DENY
        assertEquals("Observation", deny.getResourceType());
        assertTrue(deny.getOperations().contains(PermissionOperation.READ));
        assertEquals(List.of("value"), deny.getBlacklistExpressions());
    }
}
