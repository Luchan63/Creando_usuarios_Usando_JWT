package com.example.security.filters;

import com.example.models.UserEntity;
import com.example.security.jwt.JwtUtil;
import com.fasterxml.jackson.core.exc.StreamReadException;
import com.fasterxml.jackson.databind.DatabindException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

// este metodo nos ayudara a authenticarnos en la aplicaciones solo funciones para peticiones post
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter
{

    private JwtUtil jwtUtil;

    public JwtAuthenticationFilter(JwtUtil jwtUtil)
    {
        this.jwtUtil = jwtUtil;
    }
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                     HttpServletResponse response) throws AuthenticationException
    {
        UserEntity userEntity = null;
        String username;
        String password;

        try {
           userEntity = new ObjectMapper().readValue(request.getInputStream(), UserEntity.class);
           username = userEntity.getUsername();
           password = userEntity.getPassword();

        } catch (StreamReadException e) {
            throw new RuntimeException(e);
        } catch (DatabindException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        // para autenticar
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(username,password);
        return getAuthenticationManager().authenticate(authenticationToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain, Authentication authResult) throws IOException, ServletException
    {

        User user = (User) authResult.getPrincipal(); // contiene los objeto que contienen todos los usuarios
        // generamos el token de acceso
        String token = jwtUtil.generalToken(user.getUsername()); // creamos el token de acceso para darle autoridades de accesos

        response.addHeader("Authorization", token);

        Map<String,Object> httpRespose = new HashMap<>();
        httpRespose.put("token",token);
        httpRespose.put("Message","Autntication Correcta");
        httpRespose.put("Username",user.getUsername());

        response.getWriter().write(new ObjectMapper().writeValueAsString(httpRespose)); // converitmos el mapa como json
        response.setStatus(HttpStatus.OK.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().flush(); // con todo esto generamos el token
        super.successfulAuthentication(request, response, chain, authResult);


    }
}
