package com.microsoft.identity.common.internal.providers.oauth2.nativeauth.responses.sspr.cont

import com.microsoft.identity.common.internal.providers.oauth2.nativeauth.IApiResult

class SsprContinueResult private constructor(
    override val successResponse: SsprContinueResponse?,
    override val errorResponse: SsprContinueErrorResponse?
) : IApiResult() {

    companion object {
        fun createSuccess(response: SsprContinueResponse): SsprContinueResult {
            return SsprContinueResult(response, null)
        }

        fun createError(errorResponse: SsprContinueErrorResponse?): SsprContinueResult {
            return SsprContinueResult(null, errorResponse)
        }
    }
}
