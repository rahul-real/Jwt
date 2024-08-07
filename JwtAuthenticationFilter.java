package com.security.jwt.config;

import java.io.IOException;
import java.security.Key;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    
	private final Map<String, String> clientSecrets = new HashMap<>();
	
	private final List<String> audClaim = new ArrayList<>();

	public JwtAuthenticationFilter(@Value("${client.jwtSecret.one}") String clientJwtSecret1,
	                               @Value("${client.jwtSecret.two}") String clientJwtSecret2, List<String> audClaims) {
	    clientSecrets.put("7sQYF5_0LD8UmvjesNMzoQ", clientJwtSecret1);
	    clientSecrets.put("fYdfrg-0_UMp6apJNC5Uiw", clientJwtSecret2);
	    audClaim.addAll(audClaims);
	    log.info("JwtAuthenticationFilter initialized with secrets for clients: " + 
	                String.join(", ", clientSecrets.keySet()) + "and audClaims : "+ audClaim);
	}
	
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        
        String token = extractJwtFromRequest(request);
        
        if (token != null && validateToken(token)) {
            Claims claims = extractClaims(token);
            String aud = claims.getAudience();
            
            // Validate the `aud` claim
            if (aud == null || !isValidAudience(aud)) {
                log.error("Invalid audience: " + aud);
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid audience");
                return;
            }
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    claims.getSubject(), null, null);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        
        filterChain.doFilter(request, response);
    }

    private boolean isValidAudience(String aud) {
		return audClaim.contains(aud);
	}
	private String extractJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    private boolean validateToken(String token) {
        try {
            Claims claims = extractClaims(token);
            String clientSecret = getClientSecret(claims.getSubject());
            if (clientSecret != null) {
                Key key = Keys.hmacShaKeyFor(clientSecret.getBytes());
                Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
                return true;
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private Claims extractClaims(String token) {
        String clientId = null;
        try {
            // First, parse the token without verification to get the client ID
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
            	log.error("Invalid token format");
                return null;
            }
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode payloadJson = objectMapper.readTree(payload);
            clientId = payloadJson.path("sub").asText();
            
            log.info("Extracted client ID from token: " + clientId);
            
            String jwtSecret = getClientSecret(clientId);
            log.info("JWT secret for client " + clientId + ": " + (jwtSecret != null ? "found" : "not found"));
            
            if (jwtSecret == null) {
            	log.error("No secret found for client ID: " + clientId);
                return null;
            }

            // Now, parse again with the correct secret
            Key key = Keys.hmacShaKeyFor(jwtSecret.getBytes());
            return Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (Exception e) {
        	log.error("Error extracting claims from token for client " + clientId + ": " + e.getMessage(), e);
            return null;
        }
    }

    private String getClientSecret(String clientId) {
        return clientSecrets.get(clientId);
    }
}    