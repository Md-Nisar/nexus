package com.example.nexus.architecture.clifixture;

/**
 * Stand-in for a non-bean helper inside {@code rbac.interfaces.cli}, used by {@code
 * BreakGlassContainmentRuleFixturesTest} to prove the "nothing outside may depend on the cli
 * package" rule (US-018 M5 L-2) catches a laundering caller.
 */
public class CliHelperFixture {

  public void helperCall() {}
}
