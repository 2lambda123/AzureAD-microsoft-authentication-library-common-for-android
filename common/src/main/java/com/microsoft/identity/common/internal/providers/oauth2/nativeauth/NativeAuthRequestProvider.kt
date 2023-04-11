package com.microsoft.identity.common.internal.providers.oauth2.nativeauth

import com.microsoft.identity.common.internal.commands.parameters.SignInCommandParameters
import com.microsoft.identity.common.internal.commands.parameters.SignUpStartCommandParameters
import com.microsoft.identity.common.internal.commands.parameters.SsprContinueCommandParameters
import com.microsoft.identity.common.internal.commands.parameters.SsprStartCommandParameters
import com.microsoft.identity.common.internal.commands.parameters.SsprSubmitCommandParameters
import com.microsoft.identity.common.internal.providers.microsoft.microsoftsts.NativeAuthOAuth2Configuration
import com.microsoft.identity.common.internal.providers.oauth2.nativeauth.requests.signin.SignInChallengeRequest
import com.microsoft.identity.common.internal.providers.oauth2.nativeauth.requests.signin.SignInInitiateRequest
import com.microsoft.identity.common.internal.providers.oauth2.nativeauth.requests.signin.SignInTokenRequest
import com.microsoft.identity.common.internal.providers.oauth2.nativeauth.requests.signup.SignUpChallengeRequest
import com.microsoft.identity.common.internal.providers.oauth2.nativeauth.requests.signup.SignUpStartRequest
import com.microsoft.identity.common.internal.providers.oauth2.nativeauth.requests.sspr.SsprChallengeRequest
import com.microsoft.identity.common.internal.providers.oauth2.nativeauth.requests.sspr.SsprContinueRequest
import com.microsoft.identity.common.internal.providers.oauth2.nativeauth.requests.sspr.SsprPollCompletionRequest
import com.microsoft.identity.common.internal.providers.oauth2.nativeauth.requests.sspr.SsprStartRequest
import com.microsoft.identity.common.internal.providers.oauth2.nativeauth.requests.sspr.SsprSubmitRequest
import com.microsoft.identity.common.java.AuthenticationConstants
import com.microsoft.identity.common.java.logging.DiagnosticContext
import com.microsoft.identity.common.java.logging.Logger
import com.microsoft.identity.common.java.net.HttpConstants
import java.util.TreeMap

class NativeAuthRequestProvider(private val config: NativeAuthOAuth2Configuration) {
    private val TAG = NativeAuthRequestProvider::class.java.simpleName

    private val signupStartEndpoint = config.getSignUpStartEndpoint().toString()
    private val signupChallengeEndpoint = config.getSignUpChallengeEndpoint().toString()
    private val signInInitiateEndpoint = config.getSignInInitiateEndpoint().toString()
    private val signInChallengeEndpoint = config.getSignInChallengeEndpoint().toString()
    private val signInTokenEndpoint = config.getSignInTokenEndpoint().toString()
    private val ssprStartEndpoint = config.getSsprStartEndpoint().toString()
    private val ssprChallengeEndpoint = config.getSsprChallengeEndpoint().toString()
    private val ssprContinueEndpoint = config.getSsprContinueEndpoint().toString()
    private val ssprSubmitEndpoint = config.getSsprSubmitEndpoint().toString()
    private val ssprPollCompletionEndpoint = config.getSsprPollCompletionEndpoint().toString()
    private val GRANT_TYPE_PASSWORD = "password"
    private val GRANT_TYPE_OOB = "oob"
    private val GRANT_TYPE_REDIRECT = "redirect"

    //region /signup/start
    fun createSignUpStartRequest(
        commandParameters: SignUpStartCommandParameters
    ): SignUpStartRequest {
        val methodName = ":createSignUpStartRequest"
        Logger.verbose(
            TAG + methodName,
            "Creating SignUpStartRequest..."
        )

        return SignUpStartRequest.create(
            username = commandParameters.email,
            password = commandParameters.password,
            attributes = commandParameters.userAttributes,
            challengeType = config.challengeType,
            clientId = config.clientId,
            requestUrl = signupStartEndpoint,
            headers = getRequestHeaders()
        )
    }
    //endregion

    //region signup - challenge
    fun createSignUpChallengeRequest(
        signUpToken: String
    ): SignUpChallengeRequest {
        val methodName = ":createSignUpChallengeRequest"
        Logger.verbose(
            TAG + methodName,
            "Creating SignUpChallengeRequest..."
        )

        return SignUpChallengeRequest.create(
            signUpToken = signUpToken,
            clientId = config.clientId,
            challengeType = config.challengeType,
            requestUrl = signupChallengeEndpoint,
            headers = getRequestHeaders()
        )
    }
    //endregion

    //region /oauth/v2.0/initiate
    fun createSignInInitiateRequest(
        commandParameters: SignInCommandParameters
    ): SignInInitiateRequest {
        val methodName = ":createSignInInitiateRequest"
        Logger.verbose(
            TAG + methodName,
            "Creating SignInInitiateRequest..."
        )

        return SignInInitiateRequest.create(
            username = commandParameters.username,
            clientId = config.clientId,
            challengeType = config.challengeType,
            requestUrl = signInInitiateEndpoint,
            headers = getRequestHeaders()
        )
    }
    //endregion

    //region /oauth/v2.0/challenge
    fun createSignInChallengeRequest(
        credentialToken: String
    ): SignInChallengeRequest {
        val methodName = ":createSignInChallengeRequest"
        Logger.verbose(
            TAG + methodName,
            "Creating SignInChallengeRequest..."
        )

        return SignInChallengeRequest.create(
            clientId = config.clientId,
            credentialToken = credentialToken,
            challengeType = config.challengeType,
            requestUrl = signInChallengeEndpoint,
            headers = getRequestHeaders()
        )
    }
    //endregion

    //region /oauth/v2.0/token
    fun createTokenRequest(
        signInSlt: String? = null,
        credentialToken: String? = null,
        signInCommandParameters: SignInCommandParameters
    ): SignInTokenRequest {
        val methodName = ":createSignInChallengeRequest"
        Logger.verbose(
            TAG + methodName,
            "Creating SignInChallengeRequest..."
        )

        var grantType = ""
        if (!signInCommandParameters.password.isNullOrEmpty()) {
            grantType = GRANT_TYPE_PASSWORD
        } else if (!signInCommandParameters.oob.isNullOrEmpty()) {
            grantType = GRANT_TYPE_OOB
        }

        return SignInTokenRequest.create(
            username = signInCommandParameters.username,
            password = signInCommandParameters.password,
            oob = signInCommandParameters.oob,
            clientId = config.clientId,
            credentialToken = credentialToken,
            grantType = grantType,
            signInSlt = signInSlt,
            challengeType = config.challengeType,
            requestUrl = signInTokenEndpoint,
            headers = getRequestHeaders()
        )
    }
    //endregion

    //region sspr - start
    fun createSsprStartRequest(
        commandParameters: SsprStartCommandParameters
    ): SsprStartRequest {
        return SsprStartRequest.create(
            clientId = config.clientId,
            username = commandParameters.username,
            challengeType = config.challengeType,
            requestUrl = ssprStartEndpoint,
            headers = getRequestHeaders()
        )
    }

    fun createSsprChallengeRequest(
        passwordResetToken: String
    ): SsprChallengeRequest {
        return SsprChallengeRequest.create(
            clientId = config.clientId,
            passwordResetToken = passwordResetToken,
            challengeType = config.challengeType,
            requestUrl = ssprChallengeEndpoint,
            headers = getRequestHeaders()
        )
    }

    fun createSsprContinueRequest(
        passwordResetToken: String,
        commandParameters: SsprContinueCommandParameters
    ): SsprContinueRequest {
        return SsprContinueRequest.create(
            clientId = config.clientId,
            grantType = config.grantType,
            passwordResetToken = passwordResetToken,
            oob = commandParameters.oobCode,
            requestUrl = ssprContinueEndpoint,
            headers = getRequestHeaders()
        )
    }

    fun createSsprSubmitRequest(
        passwordSubmitToken: String,
        commandParameters: SsprSubmitCommandParameters
    ): SsprSubmitRequest {
        return SsprSubmitRequest.create(
            clientId = config.clientId,
            passwordSubmitToken = passwordSubmitToken,
            newPassword = commandParameters.newPassword,
            requestUrl = ssprSubmitEndpoint,
            headers = getRequestHeaders()
        )
    }

    fun createSsprPollCompletionRequest(
        passwordResetToken: String
    ): SsprPollCompletionRequest {
        return SsprPollCompletionRequest.create(
            clientId = config.clientId,
            passwordResetToken = passwordResetToken,
            requestUrl = ssprPollCompletionEndpoint,
            headers = getRequestHeaders()
        )
    }
    //endregion

    //region helpers
    private fun getRequestHeaders(): Map<String, String?> {
        // TODO why a treemap, why sorted headers?
        val headers: MutableMap<String, String?> = TreeMap()
        headers[AuthenticationConstants.AAD.CLIENT_REQUEST_ID] =
            DiagnosticContext.INSTANCE.requestContext[DiagnosticContext.CORRELATION_ID]
        headers[HttpConstants.HeaderField.CONTENT_TYPE] = "application/x-www-form-urlencoded"
        return headers
    }
    //endregion
}
