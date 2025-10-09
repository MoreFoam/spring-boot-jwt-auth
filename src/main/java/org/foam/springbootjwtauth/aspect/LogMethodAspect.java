package org.foam.springbootjwtauth.aspect;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Aspect
@Component
public class LogMethodAspect {
    private static final Logger logger = LoggerFactory.getLogger(LogMethodAspect.class);

    ObjectMapper objectMapper;

    @Autowired
    public LogMethodAspect(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Before("@annotation(org.foam.springbootjwtauth.annotation.LogMethod)")
    public void logMethodExecution(JoinPoint joinPoint) throws JsonProcessingException {
        // Get the method name
        String methodName = joinPoint.getSignature().getName();

        // Get method arguments
        Object[] args = joinPoint.getArgs();

        // Log method name and arguments
        StringBuilder logMessage = new StringBuilder("Method [")
                .append(methodName)
                .append("] started executing.");

        if (args.length > 0) {
            logMessage.append(" with arguments: ");

            for (Object arg : args) {
                logMessage.append(String.format("\n\tArgument value: %s", objectMapper.writeValueAsString(arg)));
            }
        } else {
            logMessage.append(" with no arguments.");
        }

        logger.debug(logMessage.toString());
    }

    @AfterReturning(pointcut = "@annotation(org.foam.springbootjwtauth.annotation.LogMethod)", returning = "response")
    public void logMethodResponse(JoinPoint joinPoint, Object response) throws JsonProcessingException {
        // Get the method name
        String methodName = joinPoint.getSignature().getName();

        // Log method name and response
        StringBuilder logMessage = new StringBuilder("Method [")
                .append(methodName)
                .append("] executed successfully.");

        if (response != null) {
            logMessage.append(" Response: \n\t").append(objectMapper.writeValueAsString(response));
        } else {
            logMessage.append(" Response: null");
        }

        logger.debug(logMessage.toString());
    }

}
