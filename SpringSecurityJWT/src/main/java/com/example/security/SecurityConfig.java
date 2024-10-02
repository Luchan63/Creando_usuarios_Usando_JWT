package com.example.security;

import com.example.security.filters.JwtAuthenticationFilter;
import com.example.security.filters.JwtAuthorizationFilter;
import com.example.security.jwt.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity //avilitamos las anotaciones de sprinsecurity para nuestros controladores
public class SecurityConfig
{
    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    JwtAuthorizationFilter authorizationFilter;
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity, AuthenticationManager authenticationManager) throws Exception
    {
        JwtAuthenticationFilter justAuthenticationFilter = new JwtAuthenticationFilter(jwtUtil);
        justAuthenticationFilter.setAuthenticationManager(authenticationManager);
        justAuthenticationFilter.setFilterProcessesUrl("/login");
        return httpSecurity
                .csrf(config -> config.disable())
                .sessionManagement(session -> {session.sessionCreationPolicy(SessionCreationPolicy.STATELESS);}) // manejo de la sesision})
                .addFilter(justAuthenticationFilter)
                .addFilterBefore(authorizationFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    //encriptar contraseña
    @Bean
    PasswordEncoder passwordEncoder()
    {
        return new BCryptPasswordEncoder(); // encripta en una solo via
    }

    // se encarga de la autenticacion de los usuario pero necesita un passwordEncode
    @Bean
    AuthenticationManager authenticationManager(HttpSecurity httpSecurity, PasswordEncoder passwordEncoder) throws Exception {
            return httpSecurity.getSharedObject(AuthenticationManagerBuilder.class)
                    .userDetailsService(userDetailsService)
                    .passwordEncoder(passwordEncoder)
                    .and()
                    .build();
    }

}



