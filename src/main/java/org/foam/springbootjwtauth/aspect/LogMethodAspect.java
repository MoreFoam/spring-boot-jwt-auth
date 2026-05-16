package org.foam.springbootjwtauth.aspect;

import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

import java.util.Map;
import java.util.Set;

@Aspect
@Component
public class LogMethodAspect {
    private static final Logger logger = LoggerFactory.getLogger(LogMethodAspect.class);
    private static final String REDACTED_VALUE = "[REDACTED]";
    private static final Set<String> SENSITIVE_FIELD_NAMES = Set.of(
            "accessToken",
            "authorization",
            "cookie",
            "cookies",
            "credentials",
            "password",
            "refreshToken",
            "secret",
            "setCookie",
            "token");

    private final ObjectMapper objectMapper;

    @Autowired
    public LogMethodAspect(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Before("@annotation(org.foam.springbootjwtauth.annotation.LogMethod)")
    public void logMethodExecution(JoinPoint joinPoint) {
        if (!logger.isDebugEnabled()) {
            return;
        }

        String methodName = joinPoint.getSignature().getName();

        Object[] args = joinPoint.getArgs();

        StringBuilder logMessage = new StringBuilder("Method [")
                .append(methodName)
                .append("] started executing.");

        if (args.length > 0) {
            logMessage.append(" with arguments: ");

            for (Object arg : args) {
                logMessage.append(String.format("\n\tArgument value: %s", serializeForLog(arg)));
            }
        } else {
            logMessage.append(" with no arguments.");
        }

        logger.debug(logMessage.toString());
    }

    @AfterReturning(pointcut = "@annotation(org.foam.springbootjwtauth.annotation.LogMethod)", returning = "response")
    public void logMethodResponse(JoinPoint joinPoint, Object response) {
        if (!logger.isDebugEnabled()) {
            return;
        }

        String methodName = joinPoint.getSignature().getName();

        StringBuilder logMessage = new StringBuilder("Method [")
                .append(methodName)
                .append("] executed successfully.");

        if (response != null) {
            logMessage.append(" Response: \n\t").append(serializeForLog(response));
        } else {
            logMessage.append(" Response: null");
        }

        logger.debug(logMessage.toString());
    }

    private String serializeForLog(Object value) {
        if (value == null) {
            return "null";
        }

        if (value instanceof HttpServletRequest request) {
            return serializeRequest(request);
        }

        if (value instanceof HttpServletResponse response) {
            return serializeResponse(response);
        }

        if (value instanceof ServletRequest || value instanceof ServletResponse) {
            return value.getClass().getSimpleName();
        }

        if (value instanceof ResponseEntity<?> responseEntity) {
            return serializeResponseEntity(responseEntity);
        }

        if (value instanceof CsrfToken csrfToken) {
            return serializeCsrfToken(csrfToken);
        }

        try {
            JsonNode jsonNode = objectMapper.valueToTree(value);
            redact(jsonNode);
            return objectMapper.writeValueAsString(jsonNode);
        } catch (RuntimeException e) {
            return value.getClass().getSimpleName();
        }
    }

    private String serializeRequest(HttpServletRequest request) {
        ObjectNode jsonNode = objectMapper.createObjectNode();
        jsonNode.put("type", request.getClass().getSimpleName());
        jsonNode.put("method", request.getMethod());
        jsonNode.put("requestUri", request.getRequestURI());

        String queryString = request.getQueryString();
        if (queryString != null) {
            jsonNode.put("queryString", REDACTED_VALUE);
        }

        return writeJsonNode(jsonNode);
    }

    private String serializeResponse(HttpServletResponse response) {
        ObjectNode jsonNode = objectMapper.createObjectNode();
        jsonNode.put("type", response.getClass().getSimpleName());
        jsonNode.put("status", response.getStatus());

        return writeJsonNode(jsonNode);
    }

    private String serializeResponseEntity(ResponseEntity<?> responseEntity) {
        ObjectNode jsonNode = objectMapper.createObjectNode();
        jsonNode.put("type", responseEntity.getClass().getSimpleName());
        jsonNode.put("status", responseEntity.getStatusCode().value());

        Object body = responseEntity.getBody();
        if (body == null) {
            jsonNode.put("body", (String) null);
        } else {
            JsonNode bodyNode = objectMapper.valueToTree(body);
            redact(bodyNode);
            jsonNode.set("body", bodyNode);
        }

        return writeJsonNode(jsonNode);
    }

    private String serializeCsrfToken(CsrfToken csrfToken) {
        ObjectNode jsonNode = objectMapper.createObjectNode();
        jsonNode.put("type", csrfToken.getClass().getSimpleName());
        jsonNode.put("headerName", csrfToken.getHeaderName());
        jsonNode.put("parameterName", csrfToken.getParameterName());
        jsonNode.put("token", REDACTED_VALUE);

        return writeJsonNode(jsonNode);
    }

    private void redact(JsonNode jsonNode) {
        if (jsonNode == null) {
            return;
        }

        if (jsonNode instanceof ObjectNode objectNode) {
            for (Map.Entry<String, JsonNode> property : objectNode.properties()) {
                if (isSensitiveFieldName(property.getKey())) {
                    objectNode.put(property.getKey(), REDACTED_VALUE);
                } else {
                    redact(property.getValue());
                }
            }
        } else if (jsonNode instanceof ArrayNode arrayNode) {
            for (int index = 0; index < arrayNode.size(); index++) {
                redact(arrayNode.get(index));
            }
        }
    }

    private boolean isSensitiveFieldName(String fieldName) {
        String normalizedFieldName = fieldName.toLowerCase();

        for (String sensitiveFieldName : SENSITIVE_FIELD_NAMES) {
            if (normalizedFieldName.equals(sensitiveFieldName.toLowerCase())
                    || normalizedFieldName.contains(sensitiveFieldName.toLowerCase())) {
                return true;
            }
        }

        return false;
    }

    private String writeJsonNode(JsonNode jsonNode) {
        try {
            return objectMapper.writeValueAsString(jsonNode);
        } catch (RuntimeException e) {
            return jsonNode.getClass().getSimpleName();
        }
    }
}
