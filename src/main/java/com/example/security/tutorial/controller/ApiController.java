package com.example.security.tutorial.controller;


import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ApiController {

    @GetMapping("/home")
    public String home() {
        return "Welcome to HOME page";
    }

    @GetMapping("/student")
    @PreAuthorize("hasAnyRole('STUDENT','ADMIN')")
    public String student() {
        return "Welcome to STUDENT page";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String admin() {
        return "Welcome to ADMIN page";
    }
}