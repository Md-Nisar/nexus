# Prioritisation rubric

Rank by `(blast radius x confidence) / effort`, then apply the tie-breaks.

## Tier A - fix now
1. Anything failing the **quality gate on New Code**. It blocks every merge.
2. **Security Hotspots** and vulnerabilities in `nexus-backend/src/main/**/security/**`,
   auth filters, or any endpoint handling user input. Triage these to a human
   immediately - never to the agent.
3. Bugs on hot paths: Spring `@Service`/`@Repository` classes, Angular services
   with app-wide injection scope.

## Tier B - schedule
4. High-count mechanical smells (T1). Low value each, but they are cheap,
   they shrink the noise floor, and they are the safest way to build trust in
   the automation. Start the agent here.
5. Reliability smells with clear tests already covering the code.
6. Duplicated blocks over ~50 lines - real maintenance cost, but needs design
   judgement, so route to a human.

## Tier C - defer or accept
7. Naming and convention rules. Renames touch call sites and pollute diffs.
8. Cognitive-complexity findings. Real, but splitting a method is a design
   change - human only.
9. Issues in code scheduled for deletion. Mark "Won't Fix" in Sonar instead.

## Modifiers

- **Test coverage present** -> raise a notch. Tests make a fix verifiable.
- **Zero coverage on the file** -> lower a notch for agent work. The agent has
  no safety net there, and it may not add one (tests are immutable to it).
- **File churns weekly** -> raise. Fixes there compound.
- **File untouched for a year** -> lower. Risk without reward.
- **Cross-module (Java + TS in one cluster)** -> split into two PRs.

## Effort language

Map Sonar's effort estimate to plain terms: `<=5min` trivial, `<=1h` small,
`<=1d` medium, `>1d` project. Anything above "small" is not agent work.
