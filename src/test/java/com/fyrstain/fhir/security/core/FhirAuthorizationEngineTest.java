package com.fyrstain.fhir.security.core;

import com.fyrstain.fhir.security.core.FhirAuthorizationEngine;
import com.fyrstain.fhir.security.core.MockPermissionService;
import com.fyrstain.fhir.security.core.PermissionEvaluator;
import com.fyrstain.fhir.security.core.model.FhirRequest;
import com.fyrstain.fhir.security.core.model.PermissionContext;
import com.fyrstain.fhir.security.core.model.RequestEvaluationResult;
import com.fyrstain.fhir.security.core.r4.SimpleR4PermissionEvaluator;
import org.hl7.fhir.r5.model.*;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class FhirAuthorizationEngineTest {

    private final PermissionEvaluator evaluator = new SimpleR4PermissionEvaluator();
    private final MockPermissionService permissionService = new MockPermissionService();
    private final FhirAuthorizationEngine engine = new FhirAuthorizationEngine(permissionService, evaluator);

    @Test
    void evaluateRequest_noRules() {
        PermissionContext permissionContext = new PermissionContext("userId", null, "token", null, null);

        Map<String, List<String>> searchParameters = new HashMap<>();
        searchParameters.put("myParameters", List.of("custom"));

        FhirRequest request = new FhirRequest().setMethod(FhirRequest.HTTPVerb.GET)
                .setResourceType("Patient")
                .setResourceId(null)
                .setOperationName(null)
                .setSearchParameters(searchParameters)
                .setBody(null);

        RequestEvaluationResult result = engine.evaluateRequest(permissionContext, request);

        assertFalse(result.isAllowed());
    }

    @Test
    void evaluateRequest_filterRule() {

        Permission permission = new Permission();
        permission.setStatus(Permission.PermissionStatus.ACTIVE)
               .setCombining(Permission.PermissionRuleCombining.PERMITUNLESSDENY)
               .addRule(new Permission.RuleComponent()
                       .setType(Enumerations.ConsentProvisionType.DENY)
                       .addData(new Permission.RuleDataComponent()
                               .addResource(new Permission.RuleDataResourceComponent()
                                       .setMeaning(Enumerations.ConsentDataMeaning.INSTANCE)
                                       .setReference(new Reference().setDisplay("Patient"))
                               ).setExpression(new Expression().setLanguage("text/fhirpath").setExpression("name")))
               );
        permissionService.addRule(permission);

        PermissionContext permissionContext = new PermissionContext("userId", null, "token", null, null);

        Map<String, List<String>> searchParameters = new HashMap<>();
        searchParameters.put("myParameters", List.of("custom"));

        FhirRequest request = new FhirRequest().setMethod(FhirRequest.HTTPVerb.GET)
                .setResourceType("Patient")
                .setResourceId(null)
                .setOperationName(null)
                .setSearchParameters(searchParameters)
                .setBody(null);

        RequestEvaluationResult result = engine.evaluateRequest(permissionContext, request);

        assertFalse(result.isAllowed());
        assertEquals(searchParameters, result.getModifiedSearchParameters());
    }

    @Test
    void evaluateRequest_searchParameterRule() {

        Permission permission = new Permission();
        permission.setStatus(Permission.PermissionStatus.ACTIVE)
                .setCombining(Permission.PermissionRuleCombining.DENYUNLESSPERMIT)
                .addRule(new Permission.RuleComponent()
                        .setType(Enumerations.ConsentProvisionType.PERMIT)
                        .addData(new Permission.RuleDataComponent()
                                .addResource(new Permission.RuleDataResourceComponent()
                                        .setMeaning(Enumerations.ConsentDataMeaning.INSTANCE)
                                        .setReference(new Reference().setDisplay("Patient"))
                                ).setExpression(new Expression().setLanguage("application/x-fhir-query").setExpression("name=Toto")))
                );
        permissionService.addRule(permission);

        PermissionContext permissionContext = new PermissionContext("userId", null, "token", null, null);

        Map<String, List<String>> searchParameters = new HashMap<>();
        searchParameters.put("myParameters", List.of("custom"));

        FhirRequest request = new FhirRequest().setMethod(FhirRequest.HTTPVerb.GET)
                .setResourceType("Patient")
                .setResourceId(null)
                .setOperationName(null)
                .setSearchParameters(searchParameters)
                .setBody(null);

        RequestEvaluationResult result = engine.evaluateRequest(permissionContext, request);

        assertFalse(result.isAllowed());
        assertNotEquals(searchParameters, result.getModifiedSearchParameters());
        assertEquals(List.of("Toto"), result.getModifiedSearchParameters().get("name"));
        assertEquals(List.of("custom"), result.getModifiedSearchParameters().get("myParameters"));
    }

    @Test
    void evaluateRequest_permitRule_OK() {
        Permission permission = new Permission();
        permission.setStatus(Permission.PermissionStatus.ACTIVE)
                .setCombining(Permission.PermissionRuleCombining.PERMITUNLESSDENY)
                .addRule(new Permission.RuleComponent()
                        .setType(Enumerations.ConsentProvisionType.PERMIT)
                        .addData(new Permission.RuleDataComponent()
                                .addResource(new Permission.RuleDataResourceComponent()
                                        .setMeaning(Enumerations.ConsentDataMeaning.INSTANCE)
                                        .setReference(new Reference().setDisplay("Patient"))
                                )
                        ).addActivity(new Permission.RuleActivityComponent()
                                .addAction(new CodeableConcept().addCoding(new Coding().setCode("search")))
                        )
                ).addRule(new Permission.RuleComponent()
                        .setType(Enumerations.ConsentProvisionType.DENY)
                        .addData(new Permission.RuleDataComponent()
                                .addResource(new Permission.RuleDataResourceComponent()
                                        .setMeaning(Enumerations.ConsentDataMeaning.INSTANCE)
                                        .setReference(new Reference().setDisplay("Patient"))
                                ).setExpression(new Expression().setLanguage("text/fhirpath").setExpression("name")))
                );
        permissionService.addRule(permission);

        PermissionContext permissionContext = new PermissionContext("userId", null, "token", null, null);

        FhirRequest request = new FhirRequest().setMethod(FhirRequest.HTTPVerb.GET)
                .setResourceType("Patient")
                .setResourceId(null)
                .setOperationName(null)
                .setSearchParameters(null)
                .setBody(null);

        RequestEvaluationResult result = engine.evaluateRequest(permissionContext, request);

        assertTrue(result.isAllowed());
    }

    @Test
    void evaluateRequest_permitRule_KO() {
        Permission permission = new Permission();
        permission.setStatus(Permission.PermissionStatus.ACTIVE)
                .setCombining(Permission.PermissionRuleCombining.PERMITUNLESSDENY)
                .addRule(new Permission.RuleComponent()
                        .setType(Enumerations.ConsentProvisionType.PERMIT)
                        .addData(new Permission.RuleDataComponent()
                                .addResource(new Permission.RuleDataResourceComponent()
                                        .setMeaning(Enumerations.ConsentDataMeaning.INSTANCE)
                                        .setReference(new Reference().setDisplay("Patient"))
                                )
                        ).addActivity(new Permission.RuleActivityComponent()
                                .addAction(new CodeableConcept().addCoding(new Coding().setCode("search")))
                        )
                ).addRule(new Permission.RuleComponent()
                        .setType(Enumerations.ConsentProvisionType.DENY)
                        .addData(new Permission.RuleDataComponent()
                                .addResource(new Permission.RuleDataResourceComponent()
                                        .setMeaning(Enumerations.ConsentDataMeaning.INSTANCE)
                                        .setReference(new Reference().setDisplay("Patient"))
                                ).setExpression(new Expression().setLanguage("text/fhirpath").setExpression("name")))
                );
        permissionService.addRule(permission);

        PermissionContext permissionContext = new PermissionContext("userId", null, "token", null, null);

        Map<String, List<String>> searchParameters = new HashMap<>();
        searchParameters.put("myParameters", List.of("custom"));

        FhirRequest request = new FhirRequest().setMethod(FhirRequest.HTTPVerb.POST)
                .setResourceType("Patient")
                .setResourceId(null)
                .setOperationName(null)
                .setSearchParameters(searchParameters)
                .setBody(new org.hl7.fhir.r4.model.Patient());

        RequestEvaluationResult result = engine.evaluateRequest(permissionContext, request);

        assertFalse(result.isAllowed());
        assertEquals(searchParameters, result.getModifiedSearchParameters());
    }
}
