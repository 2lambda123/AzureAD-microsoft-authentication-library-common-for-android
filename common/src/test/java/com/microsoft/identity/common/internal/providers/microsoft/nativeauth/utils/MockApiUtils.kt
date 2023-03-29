package com.microsoft.identity.common.internal.providers.microsoft.nativeauth.utils

import com.microsoft.identity.common.java.logging.DiagnosticContext
import com.microsoft.identity.common.java.logging.IRequestContext
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import org.powermock.reflect.Whitebox

class MockApiUtils {
    companion object {
        init {
            MockApi.create()
        }

        fun setCorrelationIdHeader(correlationId: String) {
            val mockDiagnosticContext = mock<DiagnosticContext>()
            Whitebox.setInternalState(
                DiagnosticContext::
                class.java,
                "INSTANCE", mockDiagnosticContext
            )

            val mockRequestContext = mock<IRequestContext>()
            whenever(mockRequestContext[DiagnosticContext.CORRELATION_ID]).thenReturn(correlationId)
            whenever(mockDiagnosticContext.requestContext).thenReturn(mockRequestContext)
        }

        fun configureMockApiResponse(endpointType: MockApiEndpointType, responseType: MockApiResponseType, correlationId: String) {
            MockApi.instance.addErrorToStack(
                endpointType = endpointType,
                responseType = responseType,
                correlationId = correlationId
            )
        }
    }
}
