package com.example.nexus.identity.interfaces.rest.dto;

/** Response body for the resend-verification endpoint (always returned, anti-enumeration). */
public record ResendVerificationResponse(String message) {}
