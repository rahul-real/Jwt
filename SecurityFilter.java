package com.security.jwt.config;

import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@EnableWebSecurity
@Configuration
@ConditionalOnProperty(name = "jwt.security.enabled", havingValue = "true")
public class SecurityFilter {

    @Value("${client.jwtSecret.one}")
    private String clientJwtSecret1;

    @Value("${client.jwtSecret.two}")
    private String clientJwtSecret2;
    
    @Value("${client.audClaims}")
	private List<String> audClaims;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(requests -> requests
                        .requestMatchers("/", "/token").permitAll()
                        .anyRequest().authenticated())
                .headers(headers -> headers
                        .cacheControl(cacheControl -> cacheControl.disable())
                        .frameOptions(frameOptions -> frameOptions.disable()))
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .addFilterBefore(new JwtAuthenticationFilter(clientJwtSecret1,clientJwtSecret2,audClaims), UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();   
        configuration.setAllowedMethods(Arrays.asList("GET","POST"));
        configuration.setAllowCredentials(true);
        configuration.setAllowedHeaders(Arrays.asList(
                "Access-Control-Allow-Origin", "Access-Control-Allow-Headers", 
                "Strict-Transport-Security", "Content-Security-Policy", 
                "x-requested-with", "Content-Type", "X-Experience-API-Version", 
                "Authorization", "Cache-Control", "Pragma", "Expires"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();     
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}