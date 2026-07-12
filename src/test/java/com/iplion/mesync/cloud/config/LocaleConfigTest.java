package com.iplion.mesync.cloud.config;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.servlet.LocaleResolver;

import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;

class LocaleConfigTest {

    private final LocaleResolver localeResolver = new LocaleConfig().localeResolver();

    @Test
    void localeResolverReturnsEnglish_whenAcceptLanguageIsMissing() {
        MockHttpServletRequest request = request();

        Locale locale = localeResolver.resolveLocale(request);

        assertThat(locale).isEqualTo(Locale.ENGLISH);
    }

    @Test
    void localeResolverReturnsRussian_whenAcceptLanguageIsRu() {
        MockHttpServletRequest request = request("ru");

        Locale locale = localeResolver.resolveLocale(request);

        assertThat(locale).isEqualTo(Locale.forLanguageTag("ru"));
    }

    @Test
    void localeResolverReturnsRussian_whenAcceptLanguageIsRuRu() {
        MockHttpServletRequest request = request("ru-RU");

        Locale locale = localeResolver.resolveLocale(request);

        assertThat(locale).isEqualTo(Locale.forLanguageTag("ru"));
    }

    @Test
    void localeResolverReturnsEnglish_whenAcceptLanguageIsUnsupported() {
        MockHttpServletRequest request = request("fr");

        Locale locale = localeResolver.resolveLocale(request);

        assertThat(locale).isEqualTo(Locale.ENGLISH);
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
