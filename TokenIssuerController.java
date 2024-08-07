package com.security.jwt.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.security.jwt.service.JwtTokenService;

import lombok.extern.slf4j.Slf4j;

@RestController
@Slf4j
public class TokenIssuerController {
	
    @Value("${client.id.one}")
    private String clientId1;

    @Value("${client.secret.one}")
    private String clientSecret1;

    @Value("${client.id.two}")
    private String clientId2;

    @Value("${client.secret.two}")
    private String clientSecret2;
    
    @Value("${client.jwtSecret.one}")
    private String clientJwtSecret1;

    @Value("${client.jwtSecret.two}")
    private String clientJwtSecret2;

	
	@Autowired
	JwtTokenService jwtTokenService;
	
	@GetMapping("/token")
	public ResponseEntity<?> generateJwtToken(@RequestParam String clientId,@RequestParam String secret,
			@RequestParam String aud){
		String jwtSecret = getJwtSecret(clientId, secret);
		log.info("jwtSecrret {} clientId1 {} clientSecret1 {} clientJwtSecret1 {} clientId2 {} clientSecret2 {} clientJwtSecret2 {} ",jwtSecret,clientId1,clientSecret1,clientJwtSecret1,clientId2,clientSecret2,clientJwtSecret2);
        if (jwtSecret != null) {
            String jwtToken = jwtTokenService.generateToken(clientId, jwtSecret, aud);
            return new ResponseEntity<>(jwtToken, HttpStatus.OK);
        } else {
            return new ResponseEntity<>("Invalid client credentials", HttpStatus.UNAUTHORIZED);
        }
    }
	
    private String getJwtSecret(String clientId, String secret) {
        if (clientId.equals(clientId1) && secret.equals(clientSecret1)) {
            return clientJwtSecret1;
        } else if (clientId.equals(clientId2) && secret.equals(clientSecret2)) {
            return clientJwtSecret2;
        } else {
            return null;
        }
    }

//	private boolean validateClient(String clientId, String secret) {
//        return (clientId.equals(clientId1) && secret.equals(clientSecret1)) ||
//               (clientId.equals(clientId2) && secret.equals(clientSecret2));
//    }
}
