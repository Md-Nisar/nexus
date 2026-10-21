package com.example.nexus.identity.infrastructure.seed;

/** Per-run tally of what the dev seed created and what it found already in place. */
final class SeedReport {

  private int created;
  private int skipped;

  void created() {
    created++;
  }

  void skipped() {
    skipped++;
  }

  int createdCount() {
    return created;
  }

  int skippedCount() {
    return skipped;
  }
}
