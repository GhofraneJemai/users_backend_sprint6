package com.example.users.security;

import java.util.Arrays;
import java.util.Collections;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import jakarta.servlet.http.HttpServletRequest;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
	
	@Autowired
	AuthenticationManager authMgr;
	
	
	
	@Bean
	 public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // Utilisation de la politique stateless

            .csrf(csrf -> csrf.disable()) // Désactivation de CSRF

            .cors(cors -> cors.configurationSource(new CorsConfigurationSource() {
                @Override
                public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                    CorsConfiguration config = new CorsConfiguration();
                    config.setAllowedOrigins(Collections.singletonList("http://localhost:4200")); // Autoriser uniquement le frontend Angular
                    config.setAllowedMethods(Collections.singletonList("*")); // Autoriser toutes les méthodes HTTP
                    config.setAllowCredentials(true); // Autoriser les informations d'identification (cookies, headers)
                    config.setAllowedHeaders(Collections.singletonList("*")); // Autoriser tous les headers
                    config.setExposedHeaders(Arrays.asList("Authorization")); // Exposer l'en-tête Authorization
                    config.setMaxAge(3600L); // Durée de mise en cache CORS
                    return config;
                }
            })) // Configuration CORS

            .authorizeHttpRequests(requests ->
                requests
                    .requestMatchers("/login").permitAll()// Permettre l'accès à /login pour tous
                    .requestMatchers("/all").hasAuthority("ADMIN") // Seuls les utilisateurs avec le rôle "ADMIN" peuvent accéder à /all
                    .anyRequest().authenticated() // Toutes les autres demandes doivent être authentifiées
            )

            .addFilterBefore(new JWTAuthenticationFilter(authMgr), UsernamePasswordAuthenticationFilter.class) // Filtrage de l'authentification JWT

            .addFilterBefore(new JWTAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class); // Filtrage de l'autorisation JWT

        return http.build();
    }
	
	

}