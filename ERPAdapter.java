// integration/erp/ERPAdapter.java
package com.phasma.ai.integration.erp;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.retry.annotation.Backoff;
import org.springframework.retry.annotation.Retryable;
import org.springframework.scheduling.annotation.Async;
import org.springframework.web.client.RestTemplate;

public abstract class ERPAdapter<T> implements ERPOperations {
    
    private static final Logger logger = LoggerFactory.getLogger(ERPAdapter.class);
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;
    private static final String AES_GCM_NO_PADDING = "AES/GCM/NoPadding";
    
    protected final RestTemplate restTemplate;
    protected final ERPConfig config;
    protected final AtomicInteger rateLimitCounter = new AtomicInteger(0);
    protected final Map<String, String> sessionTokens = new ConcurrentHashMap<>();
    
    private final ScheduledExecutorService rateLimitResetScheduler = 
        Executors.newSingleThreadScheduledExecutor();

    public ERPAdapter(ERPConfig config, RestTemplate restTemplate) {
        this.config = config;
        this.restTemplate = restTemplate;
        initializeRateLimitMonitor();
    }

    @Override
    @Retryable(value = {ERPConnectionException.class}, 
               maxAttempts = 3,
               backoff = @Backoff(delay = 1000, multiplier = 2))
    @Async("erpIntegrationTaskExecutor")
    public ResponseEntity<String> executeERPOperation(ERPOperation operation, 
                                                     Map<String, Object> payload) {
        validateAPILimits();
        refreshSessionTokenIfRequired();
        
        try {
            HttpHeaders headers = buildSecureHeaders();
            String encryptedPayload = encryptPayload(serializePayload(payload));
            
            ResponseEntity<String> response = restTemplate.exchange(
                config.getBaseUrl() + operation.getEndpoint(),
                HttpMethod.valueOf(operation.getMethod().name()),
                new HttpEntity<>(encryptedPayload, headers),
                String.class
            );
            
            if (response.getStatusCode().is2xxSuccessful()) {
                auditTransaction(operation, "SUCCESS");
                return processResponse(response);
            }
            throw new ERPResponseException("ERP system returned non-success status: " 
                + response.getStatusCode());
            
        } catch (Exception ex) {
            auditTransaction(operation, "FAILURE");
            logger.error("ERP operation failed: {}", operation.name(), ex);
            throw new ERPConnectionException("ERP integration failure", ex);
        }
    }

    protected HttpHeaders buildSecureHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + getSessionToken());
        headers.set("X-Phasma-Signature", generateRequestSignature());
        headers.set("Content-Encoding", "AES256-GCM");
        headers.set("X-API-Version", "2.3");
        headers.set("Accept", "application/json");
        return headers;
    }

    private String encryptPayload(String rawPayload) {
        try {
            byte[] iv = new byte[GCM_IV_LENGTH];
            new SecureRandom().nextBytes(iv);
            
            Cipher cipher = Cipher.getInstance(AES_GCM_NO_PADDING);
            SecretKeySpec keySpec = new SecretKeySpec(config.getEncryptionKey(), "AES");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
            
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);
            byte[] cipherText = cipher.doFinal(rawPayload.getBytes(StandardCharsets.UTF_8));
            byte[] encrypted = new byte[iv.length + cipherText.length];
            
            System.arraycopy(iv, 0, encrypted, 0, iv.length);
            System.arraycopy(cipherText, 0, encrypted, iv.length, cipherText.length);
            
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception ex) {
            logger.error("Payload encryption failed", ex);
            throw new ERPCryptoException("Data encryption failure", ex);
        }
    }

    private void initializeRateLimitMonitor() {
        rateLimitResetScheduler.scheduleAtFixedRate(() -> {
            int currentCount = rateLimitCounter.get();
            if (currentCount > 0) {
                rateLimitCounter.set(0);
                logger.info("ERP API rate limit counter reset. Current window: {}", currentCount);
            }
        }, 0, config.getRateLimitWindowSeconds(), TimeUnit.SECONDS);
    }

    protected void validateAPILimits() {
        if (rateLimitCounter.incrementAndGet() > config.getMaxRequestsPerWindow()) {
            logger.warn("ERP API rate limit exceeded: {}/{}", 
                       rateLimitCounter.get(), config.getMaxRequestsPerWindow());
            throw new ERPRateLimitException("API rate limit exceeded");
        }
    }

    protected abstract String serializePayload(Map<String, Object> payload);
    protected abstract T deserializeResponse(String responseBody);
    protected abstract void refreshSessionTokenIfRequired();
    protected abstract String getSessionToken();
    protected abstract String generateRequestSignature();
    protected abstract void auditTransaction(ERPOperation operation, String status);
    
    public interface ERPOperations {
        enum ERPOperation {
            MATERIAL_MASTER_UPDATE("/api/v1/materials", HttpMethod.PUT),
            PRODUCTION_ORDER_CREATE("/api/v1/production-orders", HttpMethod.POST),
            FINANCIAL_POSTING("/api/v2/financial-documents", HttpMethod.POST);
            
            private final String endpoint;
            private final HttpMethod method;
            
            ERPOperation(String endpoint, HttpMethod method) {
                this.endpoint = endpoint;
                this.method = method;
            }
            
            public String getEndpoint() { return endpoint; }
            public HttpMethod getMethod() { return method; }
        }
    }
    
    // Custom Exceptions
    public static class ERPConnectionException extends RuntimeException {
        public ERPConnectionException(String message, Throwable cause) {
            super(message, cause);
        }
    }
    
    public static class ERPCryptoException extends RuntimeException {
        public ERPCryptoException(String message, Throwable cause) {
            super(message, cause);
        }
    }
    
    public static class ERPRateLimitException extends RuntimeException {
        public ERPRateLimitException(String message) {
            super(message);
        }
    }
    
    public static class ERPResponseException extends RuntimeException {
        public ERPResponseException(String message) {
            super(message);
        }
    }
}

// SAP Implementation Example
class SAPAdapter extends ERPAdapter<SAPResponse> {
    
    private final SAPSessionManager sessionManager;
    private final SAPCryptographyService cryptoService;
    
    public SAPAdapter(ERPConfig config, 
                     RestTemplate restTemplate,
                     SAPSessionManager sessionManager,
                     SAPCryptographyService cryptoService) {
        super(config, restTemplate);
        this.sessionManager = sessionManager;
        this.cryptoService = cryptoService;
    }

    @Override
    protected String serializePayload(Map<String, Object> payload) {
        // Implement SAP-specific XML serialization
        return SAPXmlConverter.convertToSapXml(payload);
    }

    @Override
    protected SAPResponse deserializeResponse(String responseBody) {
        // Implement SAP-specific XML parsing
        return SAPXmlConverter.parseFromXml(responseBody);
    }

    @Override
    protected void refreshSessionTokenIfRequired() {
        if (!sessionManager.isValidSession(getSessionToken())) {
            sessionManager.refreshSession();
        }
    }

    @Override
    protected String getSessionToken() {
        return sessionManager.getCurrentSessionToken();
    }

    @Override
    protected String generateRequestSignature() {
        return cryptoService.generateHMAC(
            sessionManager.getSessionId() + System.currentTimeMillis(),
            config.getHmacSecret()
        );
    }

    @Override
    protected void auditTransaction(ERPOperation operation, String status) {
        AuditService.logERPTransaction(
            "SAP",
            operation.name(),
            status,
            cryptoService.getLastSignature()
        );
    }
}

// Configuration Record
record ERPConfig(
    String baseUrl,
    byte[] encryptionKey,
    String hmacSecret,
    int maxRequestsPerWindow,
    int rateLimitWindowSeconds,
    List<String> allowedOperations
) {}
