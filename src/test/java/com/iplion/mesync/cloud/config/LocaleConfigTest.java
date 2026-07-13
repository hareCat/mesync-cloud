package com.iplion.mesync.cloud.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.servlet.LocaleResolver;

import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;

class LocaleConfigTest {

    private final LocaleResolver localeResolver = new LocaleConfig().localeResolver();

    @Test
    void localeResolver_returnsEnglish_whenAcceptLanguageIsMissing() {
        MockHttpServletRequest request = request();

        Locale locale = localeResolver.resolveLocale(request);

        assertThat(locale).isEqualTo(Locale.ENGLISH);
    }

    @ParameterizedTest
    @CsvSource({
        "ru, ru",
        "ru-RU, ru",
        "fr, en",
        "'', en"
    })
    void localeResolver_returnsExpectedLocale_forAcceptLanguageHeader(
        String acceptLanguage,
        String expectedLanguageTag
    ) {
        MockHttpServletRequest request = request(acceptLanguage);

        Locale locale = localeResolver.resolveLocale(request);

        assertThat(locale).isEqualTo(Locale.forLanguageTag(expectedLanguageTag));
    }

    private MockHttpServletRequest request(String acceptLanguage) {
        MockHttpServletRequest request = request();
        request.addHeader("Accept-Language", acceptLanguage);
        return request;
    }

    private MockHttpServletRequest request() {
        return new MockHttpServletRequest();
    }
}
