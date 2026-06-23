package com.example.nexus.identity.interfaces.rest.dto;

public record LoginResponse(String accessToken, String tokenType, long expiresIn, String userId) {}
