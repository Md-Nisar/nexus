package com.example.nexus.common.web;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@Tag("UnitTest")
class LogMaskingUtilTest {

    // ── maskEmail ────────────────────────────────────────────────────────────

    @Test
    void maskEmail_typicalAddress_masksLocalPartAfterFirstChar() {
        assertThat(LogMaskingUtil.maskEmail("alice@example.com")).isEqualTo("a***@example.com");
    }

    @Test
    void maskEmail_singleCharLocal_returnsFirstCharPlusMask() {
        assertThat(LogMaskingUtil.maskEmail("a@b.com")).isEqualTo("a***@b.com");
    }

    @Test
    void maskEmail_noAtSign_returnsInputUnchanged() {
        assertThat(LogMaskingUtil.maskEmail("notanemail")).isEqualTo("notanemail");
    }

    @Test
    void maskEmail_null_returnsNull() {
        assertThat(LogMaskingUtil.maskEmail(null)).isNull();
    }

    // ── sanitizeCrlf ─────────────────────────────────────────────────────────

    @Test
    void sanitizeCrlf_carriageReturn_replacedWithUnderscore() {
        assertThat(LogMaskingUtil.sanitizeCrlf("foo\rbar")).isEqualTo("foo_bar");
    }

    @Test
    void sanitizeCrlf_newline_replacedWithUnderscore() {
        assertThat(LogMaskingUtil.sanitizeCrlf("foo\nbar")).isEqualTo("foo_bar");
    }

    @Test
    void sanitizeCrlf_crlfSequence_bothCharsReplaced() {
        assertThat(LogMaskingUtil.sanitizeCrlf("foo\r\nbar")).isEqualTo("foo__bar");
    }

    @Test
    void sanitizeCrlf_null_returnsNull() {
        assertThat(LogMaskingUtil.sanitizeCrlf(null)).isNull();
    }

    @Test
    void sanitizeCrlf_cleanInput_returnsUnchanged() {
        assertThat(LogMaskingUtil.sanitizeCrlf("normal text")).isEqualTo("normal text");
    }
}
