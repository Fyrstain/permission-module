package com.fyrstain.fhir.security.core.r4;

import ca.uhn.fhir.rest.server.exceptions.ResourceNotFoundException;
import com.fyrstain.fhir.security.core.model.PermissionRule;
import org.hl7.fhir.r4.model.Bundle;
import org.hl7.fhir.r4.model.Patient;
import org.junit.jupiter.api.Test;

import java.util.EnumSet;
import java.util.List;

import static com.fyrstain.fhir.security.core.model.PermissionOperation.READ;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class MatcherUtilsTest {

    @Test
    public void matchOrThrowUnsupportedCriteria() {
        Patient patient = new Patient();
        patient.addName().setFamily("Tartopom");

        PermissionRule rule = new PermissionRule("Patient", EnumSet.of(READ), true,
        List.of(), List.of("family=Test"));

        assertDoesNotThrow(() -> MatcherUtils.matchOrThrow(patient, List.of(rule)));
    }

    @Test
    public void matchOrThrowMatched() {
        Patient patient = new Patient();
        patient.addName().setFamily("Test");
        patient.addIdentifier().setSystem("system").setValue("123");
        patient.addIdentifier().setSystem("system2").setValue("456");
        patient.addIdentifier().setSystem("system3").setValue("789");

        PermissionRule rule = new PermissionRule("Patient", EnumSet.of(READ), true,
                List.of(), List.of("identifier=system2|"));

        assertDoesNotThrow(() -> MatcherUtils.matchOrThrow(patient, List.of(rule)));
    }

    @Test
    public void matchOrThrowNotMatched() {
        Patient patient = new Patient();
        patient.addName().setFamily("Test");
        patient.addIdentifier().setSystem("system").setValue("123");
        patient.addIdentifier().setSystem("system3").setValue("789");

        PermissionRule rule = new PermissionRule("Patient", EnumSet.of(READ), true,
                List.of(), List.of("identifier=system2|"));

        assertThrows(ResourceNotFoundException.class, () -> MatcherUtils.matchOrThrow(patient, List.of(rule)));
    }

    @Test
    public void matchOrThrowBundle() {
        Patient patient = new Patient();
        patient.addName().setFamily("Test");
        patient.addIdentifier().setSystem("system").setValue("123");
        patient.addIdentifier().setSystem("system3").setValue("789");

        Bundle bundle = new Bundle().addEntry(new Bundle.BundleEntryComponent().setResource(patient));

        PermissionRule rule = new PermissionRule("Patient", EnumSet.of(READ), true,
                List.of(), List.of("identifier=system2|"));

        //TODO For now, results inside Bundles are ignored (meaning reads in a transaction bypass permissions)
        assertDoesNotThrow(() -> MatcherUtils.matchOrThrow(bundle, List.of(rule)));
    }
}
