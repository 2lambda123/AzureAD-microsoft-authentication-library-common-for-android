package com.microsoft.identity.common.java.providers.nativeauth.interactors

import com.microsoft.identity.common.internal.util.getEncodedRequest
import com.microsoft.identity.common.java.commands.parameters.nativeauth.BaseNativeAuthCommandParameters
import com.microsoft.identity.common.java.commands.parameters.nativeauth.SignUpContinueCommandParameters
import com.microsoft.identity.common.java.commands.parameters.nativeauth.SignUpStartCommandParameters
import com.microsoft.identity.common.java.commands.parameters.nativeauth.SignUpStartUsingPasswordCommandParameters
import com.microsoft.identity.common.java.commands.parameters.nativeauth.SignUpSubmitCodeCommandParameters
import com.microsoft.identity.common.java.commands.parameters.nativeauth.SignUpSubmitUserAttributesCommandParameters
import com.microsoft.identity.common.java.exception.ClientException
import com.microsoft.identity.common.java.logging.LogSession
import com.microsoft.identity.common.java.net.UrlConnectionHttpClient
import com.microsoft.identity.common.java.providers.nativeauth.NativeAuthRequestProvider
import com.microsoft.identity.common.java.providers.nativeauth.NativeAuthResponseHandler
import com.microsoft.identity.common.java.providers.nativeauth.requests.signup.SignUpChallengeRequest
import com.microsoft.identity.common.java.providers.nativeauth.requests.signup.SignUpContinueRequest
import com.microsoft.identity.common.java.providers.nativeauth.requests.signup.SignUpStartRequest
import com.microsoft.identity.common.java.providers.nativeauth.responses.signup.SignUpChallengeApiResult
import com.microsoft.identity.common.java.providers.nativeauth.responses.signup.SignUpContinueApiResult
import com.microsoft.identity.common.java.providers.nativeauth.responses.signup.SignUpStartApiResult
import com.microsoft.identity.common.java.util.ObjectMapper
import com.microsoft.identity.common.java.commands.parameters.nativeauth.SignUpSubmitPasswordCommandParameters as SignUpSubmitPasswordCommandParameters1

class SignUpInteractor(
    private val httpClient: UrlConnectionHttpClient,
    private val nativeAuthRequestProvider: NativeAuthRequestProvider,
    private val nativeAuthResponseHandler: NativeAuthResponseHandler
) {
    private val TAG:String = SignUpInteractor::class.java.simpleName

    //region /signup/start
    fun performSignUpStart(
        commandParameters: SignUpStartCommandParameters
    ): SignUpStartApiResult {
        LogSession.logMethodCall(TAG, "${TAG}.performSignUpStart")

        val request = nativeAuthRequestProvider.createSignUpStartRequest(
            commandParameters = commandParameters
        )
        return performSignUpStart(request)
    }

    fun performSignUpStartUsingPassword(
        commandParameters: SignUpStartUsingPasswordCommandParameters
    ): SignUpStartApiResult {
        LogSession.logMethodCall(TAG, "${TAG}.performSignUpStartUsingPassword")
        val request = nativeAuthRequestProvider.createSignUpUsingPasswordStartRequest(
            commandParameters = commandParameters
        )
        return performSignUpStart(request)
    }

    private fun performSignUpStart(request: SignUpStartRequest): SignUpStartApiResult {
        LogSession.logMethodCall(TAG, "${TAG}.performSignUpStart")

        val encodedRequest: String = request.parameters.getEncodedRequest()
        val headers = request.headers
        val requestUrl = request.requestUrl

        val response = httpClient.post(
            requestUrl,
            headers,
            encodedRequest.toByteArray(charset(ObjectMapper.ENCODING_SCHEME))
        )
        val rawApiResponse = nativeAuthResponseHandler.getSignUpStartResultFromHttpResponse(
            response = response
        )
        return rawApiResponse.toResult()
    }
    //endregion

    //region /signup/challenge
    fun performSignUpChallenge(
        signUpToken: String
    ): SignUpChallengeApiResult {
        LogSession.logMethodCall(TAG, "${TAG}.performSignUpChallenge")

        val request = nativeAuthRequestProvider.createSignUpChallengeRequest(
            signUpToken = signUpToken
        )
        return performSignUpChallenge(request)
    }

    private fun performSignUpChallenge(request: SignUpChallengeRequest): SignUpChallengeApiResult {
        LogSession.logMethodCall(TAG, "${TAG}.performSignUpChallenge")

        val encodedRequest: String = request.parameters.getEncodedRequest()
        val headers = request.headers
        val requestUrl = request.requestUrl

        val response = httpClient.post(
            requestUrl,
            headers,
            encodedRequest.toByteArray(charset(ObjectMapper.ENCODING_SCHEME))
        )
        val rawApiResponse = nativeAuthResponseHandler.getSignUpChallengeResultFromHttpResponse(
            response = response
        )
        return rawApiResponse.toResult()
    }
    //endregion

    //region /signup/continue
    fun performSignUpSubmitCode(commandParameters: SignUpSubmitCodeCommandParameters): SignUpContinueApiResult {
        val request = nativeAuthRequestProvider.createSignUpSubmitCodeRequest(
            commandParameters = commandParameters
        )

        return performSignUpContinue(request)
    }

    fun performSignUpSubmitPassword(commandParameters: SignUpSubmitPasswordCommandParameters1): SignUpContinueApiResult {
        val request = nativeAuthRequestProvider.createSignUpSubmitPasswordRequest(
            commandParameters = commandParameters
        )

        return performSignUpContinue(request)
    }

    fun performSignUpSubmitUserAttributes(commandParameters: SignUpSubmitUserAttributesCommandParameters): SignUpContinueApiResult {
        val request = nativeAuthRequestProvider.createSignUpSubmitUserAttributesRequest(
            commandParameters = commandParameters
        )

        return performSignUpContinue(request)
    }

    private fun performSignUpContinue(request: SignUpContinueRequest): SignUpContinueApiResult {
        val encodedRequest: String = request.parameters.getEncodedRequest()
        val headers = request.headers
        val requestUrl = request.requestUrl

        val response = httpClient.post(
            requestUrl,
            headers,
            encodedRequest.toByteArray(charset(ObjectMapper.ENCODING_SCHEME))
        )
        val rawApiResponse = nativeAuthResponseHandler.getSignUpContinueResultFromHttpResponse(
            response = response
        )
        return rawApiResponse.toResult()
    }
    //endregion
}
