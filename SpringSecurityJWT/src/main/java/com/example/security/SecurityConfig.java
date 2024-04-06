package com.example.security;

import com.example.security.filters.JwtAuthenticationFilter;
import com.example.security.filters.JwtAuthorizationFilter;
import com.example.security.jwt.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
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
//                .authorizeHttpRequests(auth -> {
//                    auth.requestMatchers("/hello").permitAll();  // comportamiento de acceso
//                    auth.requestMatchers("/accessAdmin").hasRole("ADMIN"); //HASANYROLE SIRVE PARA PONER DIFERENTE ROLES HASROLE SIRVE PARA PONER UN ROL A SU ENDPOINT
////                    auth.requestMatchers("/accessUser").hasRole("USER");
////                    auth.requestMatchers("/accessInvited").hasRole("INVITED");
//                    auth.anyRequest().authenticated();
//                })
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
//    public static void main(String[] args) {
//        System.out.println(new BCryptPasswordEncoder().encode("1234"));
//    }
    // aqui creamos un suario
//    @Bean
//    UserDetailsService userDetailsService()
//    {
//        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
//        manager.createUser(User.withUsername("luisfiguereo")
//                        .password("1234")
//                        .roles()
//                        .build());
//
//        return manager;
//    }


