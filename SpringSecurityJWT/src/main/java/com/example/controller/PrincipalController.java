package com.example.controller;

import com.example.controller.request.CreateUserDTO;
import com.example.models.ERole;
import com.example.models.RolleEntity;
import com.example.models.UserEntity;
import com.example.repository.UserRepository;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Set;
import java.util.stream.Collectors;

@RestController
public class PrincipalController
{
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private UserRepository userRepository;

    @GetMapping("/hello")
    public String hello()
    {
        return "Hello World Not secured";
    }

    @GetMapping("/helloSecured")
    public String helloSecured()
    {
        return "Hello World Secure";
    }

    @PostMapping("/createUser")
    public ResponseEntity<?> createUser(@Valid @RequestBody CreateUserDTO createUserDTO)
    {
        Set<RolleEntity> roles = createUserDTO.getRoles().stream()
                .map(role -> RolleEntity.builder()
                        .name(ERole.valueOf(role))
                        .build())
                        .collect(Collectors.toSet());


        UserEntity userEntity = UserEntity.builder()
                .username(createUserDTO.getUsername())
                .password(passwordEncoder.encode(createUserDTO.getPassword()))
                .email(createUserDTO.getEmail())
                .roles(roles)
                .build();
        userRepository.save(userEntity);

        return ResponseEntity.ok(userEntity);
    }

    @DeleteMapping("/deleteUser")
    public String deleteUser(@RequestParam String id)
    {
        userRepository.deleteById(Long.parseLong(id));

        return "Se Ha borrado Exitosamente";
    }
}
