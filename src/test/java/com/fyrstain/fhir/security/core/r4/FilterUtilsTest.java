package com.fyrstain.fhir.security.core.r4;

import org.hl7.fhir.r4.model.*;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class FilterUtilsTest {

    @Test
    void removeFieldsByExpression_shouldRemoveSimpleField() {
        // Arrange
        Patient patient = new Patient();
        patient.addName().setFamily("Doe").addGiven("John");
        patient.addTelecom().setValue("123456").setSystem(ContactPoint.ContactPointSystem.PHONE);

        assertThat(patient.hasTelecom()).isTrue();

        // Act
        FilterUtils.removeFieldsByExpression(patient, List.of("Patient.telecom"));

        // Assert
        assertThat(patient.hasTelecom()).isFalse();
        assertThat(patient.getNameFirstRep().getFamily()).isEqualTo("Doe");
    }

    @Test
    void removeFieldsByExpression_shouldRemoveOneInList() {
        // Arrange
        Patient patient = new Patient();
        patient.addName().setFamily("Doe").addGiven("John");
        patient.addTelecom().setValue("123456").setSystem(ContactPoint.ContactPointSystem.PHONE);
        patient.addTelecom().setValue("mail@mail.mail").setSystem(ContactPoint.ContactPointSystem.EMAIL);
        patient.addTelecom().setValue("12131415").setSystem(ContactPoint.ContactPointSystem.PHONE);

        assertThat(patient.hasTelecom()).isTrue();

        // Act
        FilterUtils.removeFieldsByExpression(patient, List.of("Patient.telecom.where(system='email')"));

        // Assert
        assertThat(patient.hasTelecom()).isTrue();
        assertThat(patient.getTelecom().size()).isEqualTo(2);
        assertThat(patient.getTelecom().stream().allMatch(t -> ContactPoint.ContactPointSystem.PHONE.equals(t.getSystem()))).isTrue();
        assertThat(patient.getNameFirstRep().getFamily()).isEqualTo("Doe");
    }

    @Test
    void removeFieldsByExpression_shouldRemoveNestedElement() {
        // Arrange
        Observation obs = new Observation();
        obs.setStatus(Observation.ObservationStatus.FINAL);
        obs.getCode().addCoding().setSystem("http://loinc.org").setCode("1234-5");
        obs.setValue(new Quantity().setValue(12.3).setUnit("mg"));

        assertThat(obs.hasValueQuantity()).isTrue();

        // Act
        FilterUtils.removeFieldsByExpression(obs, List.of("Observation.value"));

        // Assert
        assertThat(obs.hasValueQuantity()).isFalse();
        assertThat(obs.getCode().getCodingFirstRep().getCode()).isEqualTo("1234-5");
    }

    @Test
    void removeFieldsByExpression_shouldApplyToBundleEntries() {
        // Arrange
        Patient patient1 = new Patient();
        patient1.addName().setFamily("Doe");
        patient1.addTelecom().setValue("11111");

        Patient patient2 = new Patient();
        patient2.addName().setFamily("Smith");
        patient2.addTelecom().setValue("22222");

        Bundle bundle = new Bundle();
        bundle.addEntry().setResource(patient1);
        bundle.addEntry().setResource(patient2);

        // Act
        FilterUtils.removeFieldsByExpression(bundle, List.of("Patient.telecom"));

        // Assert
        for (Bundle.BundleEntryComponent entry : bundle.getEntry()) {
            Patient p = (Patient) entry.getResource();
            assertThat(p.hasTelecom()).isFalse();
            assertThat(p.getNameFirstRep().getFamily()).isNotNull();
        }
    }

    @Test
    void removeFieldsByExpression_shouldIgnoreInvalidPath() {
        // Arrange
        Patient patient = new Patient();
        patient.addName().setFamily("Test");

        // Should not throw
        FilterUtils.removeFieldsByExpression(patient, List.of("Patient.invalidField"));

        assertThat(patient.hasName()).isTrue();
    }
}
