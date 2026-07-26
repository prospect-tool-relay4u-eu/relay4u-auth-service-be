package eu.relay4u.authservicebe.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.slf4j.MDC;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CorrelationIdFilterTest {

    private final CorrelationIdFilter filter = new CorrelationIdFilter();

    @Test
    void doFilter_withoutHeader_generatesCorrelationIdAndSetsResponseHeader() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);
        when(request.getHeader(CorrelationIdFilter.HEADER_NAME)).thenReturn(null);

        filter.doFilter(request, response, chain);

        ArgumentCaptor<String> headerValue = ArgumentCaptor.forClass(String.class);
        verify(response).setHeader(org.mockito.ArgumentMatchers.eq(CorrelationIdFilter.HEADER_NAME), headerValue.capture());
        assertThat(headerValue.getValue()).isNotBlank();
        verify(chain).doFilter(request, response);
        assertThat(MDC.get(CorrelationIdFilter.MDC_KEY)).isNull();
    }

    @Test
    void doFilter_withExistingHeader_reusesProvidedCorrelationId() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);
        when(request.getHeader(CorrelationIdFilter.HEADER_NAME)).thenReturn("given-correlation-id");

        filter.doFilter(request, response, chain);

        verify(response).setHeader(CorrelationIdFilter.HEADER_NAME, "given-correlation-id");
        verify(chain).doFilter(request, response);
    }

    @Test
    void doFilter_withBlankHeader_generatesNewCorrelationId() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);
        when(request.getHeader(CorrelationIdFilter.HEADER_NAME)).thenReturn("   ");

        filter.doFilter(request, response, chain);

        ArgumentCaptor<String> headerValue = ArgumentCaptor.forClass(String.class);
        verify(response).setHeader(org.mockito.ArgumentMatchers.eq(CorrelationIdFilter.HEADER_NAME), headerValue.capture());
        assertThat(headerValue.getValue()).isNotBlank().isNotEqualTo("   ");
    }

    @Test
    void doFilter_clearsMdcEvenWhenChainThrows() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);
        when(request.getHeader(CorrelationIdFilter.HEADER_NAME)).thenReturn(null);

        org.junit.jupiter.api.function.ThrowingSupplier<Void> action = () -> {
            org.mockito.Mockito.doThrow(new RuntimeException("boom")).when(chain).doFilter(request, response);
            filter.doFilter(request, response, chain);
            return null;
        };

        assertThat(org.junit.jupiter.api.Assertions.assertThrows(RuntimeException.class, action::get))
                .hasMessage("boom");
        assertThat(MDC.get(CorrelationIdFilter.MDC_KEY)).isNull();
    }
}
