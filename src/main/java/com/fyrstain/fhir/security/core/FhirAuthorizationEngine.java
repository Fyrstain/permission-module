package com.fyrstain.fhir.security.core;

import com.fyrstain.fhir.security.core.model.*;
import org.hl7.fhir.instance.model.api.IBaseResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public class FhirAuthorizationEngine {

    private static final Logger logger = LoggerFactory.getLogger(FhirAuthorizationEngine.class);

    private final PermissionService permissionService;
    private final PermissionEvaluator evaluator;

    /**
     * Default constructor for the class.
     *
     * @param permissionService used to retrieve Permission resources. Implementation may vary depending on where/how the resources are stored.
     * @param evaluator         evaluation service for the permission. Implementation may vary depending on how rules should be enforced.
     */
    public FhirAuthorizationEngine(PermissionService permissionService, PermissionEvaluator evaluator) {
        this.permissionService = permissionService;
        this.evaluator = evaluator;
    }

    /**
     * Evaluates the request vis-à-vis the Permission resources. This determines if the operation is allowed, and if some
     * filter needs to be applied to the original request to ensure the correct scope.
     *
     * @param context the authorization context, containing information on the Permission to retrieve
     * @param request the request that was sent to the server. Used to check permission for what is requested.
     *
     * @return a {@link RequestEvaluationResult} that contains the result of Permission evaluation.
     */
    public RequestEvaluationResult evaluateRequest(
            PermissionContext context,
            FhirRequest request) {
        List<PermissionRule> rules = getRules(context);

        //Build and return the evaluation result.
        return new RequestEvaluationResult(
                evaluator.canPerform(request.getResourceType(), request.getOperation(), rules),
                evaluator.updateSearchParameters(request.getSearchParameters(), rules),
                rules,
                null);
    }

    public FhirResponse filterResponse(
            PermissionContext context,
            FhirResponse response) {
        return evaluator.filterResponse(response, getRules(context));
    }

    private List<PermissionRule> getRules(PermissionContext context) {
        //Retrieve Permission resources (depends on context)
        List<IBaseResource> permissions = permissionService.getPermissions(context);
        //Compile FHIR Permission resources into a computable set of resource the engine can interpret
        return evaluator.compileRules(permissions);
    }
}
