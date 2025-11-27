package com.fyrstain.fhir.security.adapter.iris;

import ca.uhn.fhir.context.FhirContext;
import com.fyrstain.fhir.security.core.FhirAuthorizationEngine;
import com.fyrstain.fhir.security.core.PermissionService;
import com.fyrstain.fhir.security.core.model.FhirRequest;
import com.fyrstain.fhir.security.core.model.FhirResponse;
import com.fyrstain.fhir.security.core.model.PermissionContext;
import com.fyrstain.fhir.security.core.model.RequestEvaluationResult;
import com.fyrstain.fhir.security.core.r4.SimpleR4PermissionEvaluator;
import org.hl7.fhir.instance.model.api.IBaseResource;
import org.hl7.fhir.r4.formats.JsonParser;
import org.hl7.fhir.r4.model.Resource;

import java.io.ByteArrayOutputStream;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

public class JavaPermissionFacade {

    private static final FhirAuthorizationEngine AUTHORIZATION_ENGINE;

    static {
        AUTHORIZATION_ENGINE = new FhirAuthorizationEngine(
                /*TODO A voir comment on passe ça !*/ new MockPermissionService()
                , new SimpleR4PermissionEvaluator());
    }

    public static String evaluateRequest(
            String userId,
            String token,
            String httpVerb,
            String resourceType,
            String resourceId,
            String operationName,
            String searchParameters,
            String body
    ) throws Throwable {

        PermissionContext permissionContext = new PermissionContext(userId, null, token, null, null);

        FhirRequest request = new FhirRequest().setMethod(FhirRequest.HTTPVerb.valueOf(httpVerb))
                .setResourceType(resourceType)
                .setResourceId(resourceId)
                .setOperationName(operationName)
                .setSearchParameters(parseSearchParameters(searchParameters))
                .setBody(deserialize(body));

        RequestEvaluationResult requestEvaluationResult = AUTHORIZATION_ENGINE.evaluateRequest(permissionContext, request);

        if (!requestEvaluationResult.isAllowed()) {
            throw new Exception("Method not allowed");
        }

        return toQueryString(requestEvaluationResult.getModifiedSearchParameters());
    }

    private static String toQueryString(Map<String, List<String>> params) {
        return params.entrySet().stream()
                .map(entry -> entry.getKey() + "=" +
                        entry.getValue().stream()
                                .map(v -> URLEncoder.encode(v, StandardCharsets.UTF_8))
                                .collect(Collectors.joining(",")))
                .collect(Collectors.joining("&"));
    }

    public String filterResponse(
            String userId,
            String token,
            String statusCode,
            String responseBody
    ) throws Throwable {

        PermissionContext permissionContext = new PermissionContext(userId, null, token, null, null);
        FhirResponse response = new FhirResponse()
                .setStatusCode(Integer.getInteger(statusCode))
                .setResource(deserialize(responseBody));

        FhirResponse updatedResponse = AUTHORIZATION_ENGINE.filterResponse(permissionContext, response);

        return serialize(updatedResponse.getResource());
    }

    private static String serialize(IBaseResource resource) throws Throwable
    {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        new JsonParser().setOutputStyle(org.hl7.fhir.r4.formats.IParser.OutputStyle.PRETTY).compose(os, (Resource) resource);
        os.close();
        return os.toString();
    }

    private static IBaseResource deserialize(String resourceAsString) throws Throwable {
        if (resourceAsString == null) {
            return null;
        }
        return new JsonParser().parse(resourceAsString);
    }

    public static Map<String, List<String>> parseSearchParameters(String queryString) {
        Map<String, List<String>> map = new LinkedHashMap<>();

        if (queryString == null || queryString.isEmpty()) {
            return map;
        }

        String[] pairs = queryString.split("&");
        for (String pair : pairs) {
            String[] kv = pair.split("=", 2);
            String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
            String value = kv.length > 1 ? kv[1] : "";

            List<String> values = new ArrayList<>();
            for (String v : value.split(",")) {
                values.add(URLDecoder.decode(v, StandardCharsets.UTF_8));
            }

            map.put(key, values);
        }

        return map;
    }

    static class MockPermissionService implements PermissionService {

        @Override
        public List<IBaseResource> getPermissions(PermissionContext context) {
            return List.of();
        }
    }
}
