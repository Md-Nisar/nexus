package com.example.nexus.identity.interfaces.rest.dto;

/** Response body for a successful (or silently acknowledged duplicate) registration. */
public record RegisterResponse(String message) {}
