package com.example.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@PreAuthorize("denyAll()")
public class TestRolesController
{
    @GetMapping("/accessAdmin")
    @PreAuthorize("hasRole('ADMIM')")
    public String accessAdmin()
    {
        return "Hola has accedido con rol de Admin";
    }

    @GetMapping("/accessUser")
    @PreAuthorize("hasRole('USER')") // podemos usar or hasRole si queremos varios usuarios con permiso o hasAnyRole
    public String accessUser()
    {
        return "Hola has accedido con rol de User";
    }

    @GetMapping("/accessInvited")
    @PreAuthorize("hasRole('INVITED')")
    public String accessInvited()
    {
        return "Hola has accedido con rol de Invited";
    }
}
