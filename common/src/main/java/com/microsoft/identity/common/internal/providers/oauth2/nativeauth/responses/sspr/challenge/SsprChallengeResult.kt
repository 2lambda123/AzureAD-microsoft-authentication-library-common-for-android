package com.microsoft.identity.common.internal.providers.oauth2.nativeauth.responses.sspr.challenge

import com.microsoft.identity.common.internal.providers.oauth2.nativeauth.IApiResult

class SsprChallengeResult private constructor(
    override val successResponse: SsprChallengeResponse?,
    override val errorResponse: SsprChallengeErrorResponse?
) : IApiResult() {

    companion object {
        fun createSuccess(response: SsprChallengeResponse): SsprChallengeResult {
            return SsprChallengeResult(response, null)
        }

        fun createError(errorResponse: SsprChallengeErrorResponse?): SsprChallengeResult {
            return SsprChallengeResult(null, errorResponse)
        }
    }
}
