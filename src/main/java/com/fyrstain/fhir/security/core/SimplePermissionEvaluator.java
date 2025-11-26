package com.fyrstain.fhir.security.core;

import ca.uhn.fhir.context.FhirContext;
import ca.uhn.fhir.context.FhirVersionEnum;
import com.fyrstain.fhir.security.core.model.PermissionOperation;
import com.fyrstain.fhir.security.core.model.PermissionRule;
import org.hl7.fhir.instance.model.api.IBaseResource;
import org.hl7.fhir.r5.model.CodeType;
import org.hl7.fhir.r5.model.Permission;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.stream.Collectors;

import static org.hl7.fhir.r5.model.Enumerations.ConsentDataMeaning.INSTANCE;
import static org.hl7.fhir.r5.model.Enumerations.ConsentProvisionType.PERMIT;

public abstract class SimplePermissionEvaluator implements PermissionEvaluator {

    private static final Logger logger = LoggerFactory.getLogger(SimplePermissionEvaluator.class);

    /**
     * {@inheritDoc}
     */
    @Override
    public List<PermissionRule> compileRules(List<IBaseResource> permissionResources) {
        List<PermissionRule> rules = new ArrayList<>();

        for (IBaseResource resource : permissionResources) {
            //Ignore resources that would not be Permissions
            if (!(resource instanceof Permission)) continue;
            // Ignore permission that are not active
            if (!((Permission) resource).getStatus().equals(Permission.PermissionStatus.ACTIVE)) {
                logger.warn("Ignoring inactive Permission {}", ((Permission) resource).getIdPart());
                continue;
            }

            //TODO See for combining element (deny-overrides, permit-overrides, etc)

            // For active subscription, loop on rules and add a new rule for each resource mentioned
            for (Permission.RuleComponent rule : ((Permission) resource).getRule()) {
                boolean allow = rule.getType().equals(PERMIT);

                Map<String, List<String>> resourceTypes = new HashMap<>();
                rule.getData().forEach(data -> {
                    data.getResource().forEach(dataResource -> {
                        //Only instance is supported here
                        if (!dataResource.getMeaning().equals(INSTANCE)) {
                            logger.warn("Ignoring rule in Permission {} that is not for a resource INSTANCE (not supported {})",
                                    ((Permission) resource).getIdPart(), dataResource.getMeaning());
                            return;
                        }

                        //Add resource types as displayed in the resource reference
                        Optional.ofNullable(dataResource.getReference().getDisplay())
                                .ifPresent(type -> resourceTypes.putIfAbsent(type, new ArrayList<>()));

                        //Only support blacklisting elements for now.
                        //Only support FHIRPath for now.
                        if (!allow
                                && dataResource.getReference().getDisplay() != null
                                && data.hasExpression()
                                && data.getExpression().hasLanguage()
                                && "text/fhirpath".equals(data.getExpression().getLanguage())) {
                            List<String> expressions = resourceTypes.get(dataResource.getReference().getDisplay());
                            if (expressions != null && data.getExpression().hasExpression()) {
                                expressions.add(data.getExpression().getExpression());
                            }
                        }
                    });
                });

                EnumSet<PermissionOperation> operations = EnumSet.noneOf(PermissionOperation.class);

                logger.warn(FhirContext.forCached(FhirVersionEnum.R5).newJsonParser().encodeToString(resource));

                // Get all codes from rule.activity.action to define restricted operations
                for (CodeType code : rule.getActivity().stream()
                        .flatMap(a -> a.getAction().stream())
                        .flatMap(a -> a.getCoding().stream())
                        .map(c -> new CodeType(c.getCode()))
                        .collect(Collectors.toList())) {
                    switch (code.getValue().toLowerCase()) {
                        case "read":
                            operations.add(PermissionOperation.READ);
                            break;
                        case "search":
                            operations.add(PermissionOperation.SEARCH);
                            break;
                        case "create":
                            operations.add(PermissionOperation.CREATE);
                            break;
                        case "update":
                            operations.add(PermissionOperation.UPDATE);
                            break;
                        case "delete":
                            operations.add(PermissionOperation.DELETE);
                            break;
                        case "patch":
                            operations.add(PermissionOperation.PATCH);
                            break;
                        default:
                            operations.add(PermissionOperation.CUSTOM);
                    }
                }

                //Create a permission rule for operations for each resource type found in rule.data
                resourceTypes.forEach((resourceType, expressions) ->
                        rules.add(new PermissionRule(resourceType, operations, allow, expressions)));
            }
        }
        return rules;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean canPerform(String resourceType, PermissionOperation op, List<PermissionRule> rules) {
        //TODO See what is the default behavior (maybe can be configured) ? Do we allow-all or deny-all by default
        if(rules.isEmpty()) {
            return true;
        }
        return rules.stream().noneMatch(r -> r.denies(resourceType, op)) && rules.stream().anyMatch(r -> r.allows(resourceType, op));
    }
}
