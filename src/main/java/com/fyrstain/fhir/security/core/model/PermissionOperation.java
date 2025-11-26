package com.fyrstain.fhir.security.core.model;

//TODO Is this enough to handle custom operations ??
public enum PermissionOperation {
    READ, CREATE, UPDATE, DELETE, SEARCH, PATCH, CUSTOM;
}
