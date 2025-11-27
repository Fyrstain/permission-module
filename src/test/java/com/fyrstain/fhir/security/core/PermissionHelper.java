package com.fyrstain.fhir.security.core;

import org.hl7.fhir.r5.model.CodeableConcept;
import org.hl7.fhir.r5.model.Enumerations;
import org.hl7.fhir.r5.model.Expression;
import org.hl7.fhir.r5.model.Permission;

public class PermissionHelper {

    public static Permission buildPermission(boolean active) {
        Permission p = new Permission();
        p.setId("Permission/123");
        p.setStatus(active ?
                Permission.PermissionStatus.ACTIVE :
                Permission.PermissionStatus.DRAFT);
        return p;
    }

    public static Permission.RuleComponent newRule(boolean allow) {
        Permission.RuleComponent rule = new Permission.RuleComponent();
        rule.setType(allow ? Enumerations.ConsentProvisionType.PERMIT : Enumerations.ConsentProvisionType.DENY);
        return rule;
    }

    public static Permission.RuleDataComponent dataForInstance(
            String resourceType, String fhirPath, String search
    ) {
        Permission.RuleDataComponent data = new Permission.RuleDataComponent();


        // reference.display holds the resource type
        Permission.RuleDataResourceComponent res = data.getResourceFirstRep();

        res.setMeaning(Enumerations.ConsentDataMeaning.INSTANCE);
        res.getReference().setDisplay(resourceType);

        if (fhirPath != null) {
            Expression exp = new Expression();
            exp.setLanguage("text/fhirpath");
            exp.setExpression(fhirPath);
            data.setExpression(exp);
        }

        if (search != null) {
            Expression exp = new Expression();
            exp.setLanguage("application/x-fhir-query");
            exp.setExpression(search);
            data.setExpression(exp);
        }

        return data;
    }

    public static Permission.RuleActivityComponent activity(String... actions) {
        Permission.RuleActivityComponent act = new Permission.RuleActivityComponent();
        CodeableConcept cc = new CodeableConcept();
        for (String a : actions) {
            cc.addCoding().setCode(a);
        }
        act.addAction(cc);
        return act;
    }
}
