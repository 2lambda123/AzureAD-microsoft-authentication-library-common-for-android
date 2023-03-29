package com.microsoft.identity.common.internal.providers.oauth2.nativeauth.responses.signup

class SignUpChallengeResult private constructor(
    override val successResponse: SignUpChallengeResponse?,
    override val errorResponse: SignUpChallengeErrorResponse?
) : com.microsoft.identity.common.internal.providers.oauth2.nativeauth.IApiResult() {

    companion object {
        fun createSuccess(response: SignUpChallengeResponse): SignUpChallengeResult {
            return SignUpChallengeResult(response, null)
        }

        fun createError(errorResponse: SignUpChallengeErrorResponse?): SignUpChallengeResult {
            return SignUpChallengeResult(null, errorResponse)
        }
    }
}
