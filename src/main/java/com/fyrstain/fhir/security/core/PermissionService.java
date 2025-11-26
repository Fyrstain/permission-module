package com.fyrstain.fhir.security.core;

import com.fyrstain.fhir.security.core.model.PermissionContext;
import org.hl7.fhir.instance.model.api.IBaseResource;

import java.util.List;

public interface PermissionService {
    /**
     * Retrieves all Permission resources associated with the current user.
     */
    List<IBaseResource> getPermissions(PermissionContext context);
}
