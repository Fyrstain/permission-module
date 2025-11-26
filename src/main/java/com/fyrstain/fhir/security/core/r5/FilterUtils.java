package com.fyrstain.fhir.security.core.r5;

import ca.uhn.fhir.context.BaseRuntimeChildDefinition;
import ca.uhn.fhir.context.FhirContext;
import ca.uhn.fhir.context.FhirVersionEnum;
import ca.uhn.fhir.context.RuntimeResourceDefinition;
import org.hl7.fhir.instance.model.api.IBase;
import org.hl7.fhir.instance.model.api.IBaseResource;
import org.hl7.fhir.r5.context.SimpleWorkerContext;
import org.hl7.fhir.r5.fhirpath.FHIRPathEngine;
import org.hl7.fhir.r5.model.Base;
import org.hl7.fhir.r5.model.Bundle;
import org.hl7.fhir.r5.model.Resource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Util class for filtering resource content.
 */
public class FilterUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(FilterUtils.class);

    private static final FhirContext CONTEXT = FhirContext.forCached(FhirVersionEnum.R5);
    private static final FHIRPathEngine FHIR_PATH_ENGINE;

    static {
        try {
            FHIR_PATH_ENGINE = new FHIRPathEngine(new SimpleWorkerContext.SimpleWorkerContextBuilder().build());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Removes elements from a resource based on FHIRPath expressions.
     *
     * @param resource    The resource to filter (IBaseResource / Resource)
     * @param expressions List of FHIRPath expressions to remove
     */
    public static void removeFieldsByExpression(IBaseResource resource, List<String> expressions) {
        if (resource == null || expressions == null) return;

        // Handle bundles recursively
        if (resource instanceof Bundle) {
            for (Bundle.BundleEntryComponent entry : ((Bundle) resource).getEntry()) {
                if (entry.getResource() != null)
                    removeFieldsByExpression(entry.getResource(), expressions);
            }
            return;
        }

        for (String expression : expressions) {
            try {
                List<Base> matches = FHIR_PATH_ENGINE.evaluate((Base) resource, FHIR_PATH_ENGINE.parse(expression));

                for (Base match : matches) {
                    removeElement((Resource) resource, match);
                }
            } catch (Exception e) {
                // TODO See for exception here ?
                LOGGER.error("Failed to apply FHIRPath expression '{}': {}", expression, e.getMessage());
            }
        }
    }

    /**
     * Removes a Base element from its parent.
     *
     * @param resource the resource from which the element should be removed
     * @param toRemove the element to remove
     */
    private static void removeElement(Resource resource, Base toRemove) {
        if (resource == null || toRemove == null) return;

        RuntimeResourceDefinition def = CONTEXT.getResourceDefinition(resource);
        removeFromChildren(resource, toRemove, def.getChildren());
    }

    /**
     * Recursively remove element from children.
     *
     * @param parent    the current level of the browsed resource.
     * @param target    the target element to remove.
     * @param children  the list of children to browse.
     */
    private static void removeFromChildren(Base parent, Base target, List<BaseRuntimeChildDefinition> children) {
        for (BaseRuntimeChildDefinition childDef : children) {
            List<IBase> values = new ArrayList<>(childDef.getAccessor().getValues(parent));
            if (values == null || values.isEmpty()) continue;

            // Remove target if present
            if (safeRemoveChild(childDef, parent, target)) {
                return;
            }

            // Recurse into child elements
            for (IBase child : values) {
                // Get child definition if possible
                List<BaseRuntimeChildDefinition> grandChildren = List.of();

                try {
                    //TODO Remove one after testing !
                    List<BaseRuntimeChildDefinition> grandChildren2 = childDef.getChildElementDefinitionByDatatype(child.getClass()).getChildren();

                    if (child instanceof Resource)
                        grandChildren = CONTEXT.getResourceDefinition((Resource) child).getChildren();
                    else if (childDef.getChildByName(childDef.getElementName()) != null)
                        grandChildren = childDef.getChildByName(childDef.getElementName()).getChildren();
                } catch (Exception e) {
                    LOGGER.warn("Error getting children elements : {}", e.getMessage());
                }

                if (child instanceof Resource) {
                    removeElement((Resource) child, target);
                } else if (child instanceof Base) {
                    removeFromChildren((Base) child, target, grandChildren);
                }
            }
        }
    }

    /**
     * Remove a child value.
     *
     * @param childDef  the child definition
     * @param parent    the parent element
     * @param target    the element to remove
     * @return  true if the element was remove, false otherwise.
     */
    private static boolean safeRemoveChild(BaseRuntimeChildDefinition childDef, Base parent, Base target) {
        List<IBase> values = new ArrayList<>(childDef.getAccessor().getValues(parent));

        for (int i = 0; i < values.size(); i++) {
            if (values.get(i) instanceof Base && ((Base) values.get(i)).equalsDeep(target)) {
                if (childDef.isMultipleCardinality()) {
                    childDef.getMutator().remove(parent, i);
                } else {
                    childDef.getMutator().setValue(parent, null);
                }
                return true;
            }
        }
        return false;
    }
}
