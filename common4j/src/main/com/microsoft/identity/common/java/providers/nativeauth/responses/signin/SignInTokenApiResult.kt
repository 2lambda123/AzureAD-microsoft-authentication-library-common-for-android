package com.microsoft.identity.common.java.providers.nativeauth.responses.signin

import com.microsoft.identity.common.java.providers.microsoft.microsoftsts.MicrosoftStsTokenResponse

sealed interface SignInTokenApiResult {
    object Redirect : SignInTokenApiResult
    data class Success(val tokenResponse: MicrosoftStsTokenResponse) : SignInTokenApiResult
    data class CredentialRequired(val credentialToken: String) : SignInTokenApiResult
    data class UserNotFound(val error: String, val errorDescription: String) : SignInTokenApiResult
    data class PasswordIncorrect(val error: String, val errorDescription: String) : SignInTokenApiResult
    data class CodeIncorrect(val error: String, val errorDescription: String) : SignInTokenApiResult
    data class UnknownError(val error: String?, val errorDescription: String?) :
        SignInTokenApiResult
}