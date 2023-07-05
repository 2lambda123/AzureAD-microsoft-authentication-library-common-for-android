//  Copyright (c) Microsoft Corporation.
//  All rights reserved.
//
//  This code is licensed under the MIT License.
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files(the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions :
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.
package com.microsoft.identity.common.internal.providers.microsoft.nativeauth.integration

import android.os.Build
import com.microsoft.identity.common.internal.providers.microsoft.nativeauth.utils.ApiConstants
import com.microsoft.identity.common.internal.providers.microsoft.nativeauth.utils.MockApiEndpointType
import com.microsoft.identity.common.internal.providers.microsoft.nativeauth.utils.MockApiResponseType
import com.microsoft.identity.common.internal.providers.microsoft.nativeauth.utils.MockApiUtils
import com.microsoft.identity.common.java.commands.parameters.nativeauth.SignInStartCommandParameters
import com.microsoft.identity.common.java.commands.parameters.nativeauth.SignInStartUsingPasswordCommandParameters
import com.microsoft.identity.common.java.commands.parameters.nativeauth.SignInSubmitCodeCommandParameters
import com.microsoft.identity.common.java.commands.parameters.nativeauth.SignInSubmitPasswordCommandParameters
import com.microsoft.identity.common.java.commands.parameters.nativeauth.SignInWithSLTCommandParameters
import com.microsoft.identity.common.java.interfaces.PlatformComponents
import com.microsoft.identity.common.java.logging.DiagnosticContext
import com.microsoft.identity.common.java.net.UrlConnectionHttpClient
import com.microsoft.identity.common.java.providers.nativeauth.NativeAuthOAuth2Configuration
import com.microsoft.identity.common.java.providers.nativeauth.NativeAuthOAuth2Strategy
import com.microsoft.identity.common.java.providers.nativeauth.NativeAuthRequestProvider
import com.microsoft.identity.common.java.providers.nativeauth.NativeAuthResponseHandler
import com.microsoft.identity.common.java.providers.nativeauth.interactors.ResetPasswordInteractor
import com.microsoft.identity.common.java.providers.nativeauth.interactors.SignInInteractor
import com.microsoft.identity.common.java.providers.nativeauth.interactors.SignUpInteractor
import com.microsoft.identity.common.java.providers.nativeauth.responses.signin.SignInChallengeApiResult
import com.microsoft.identity.common.java.providers.nativeauth.responses.signin.SignInInitiateApiResult
import com.microsoft.identity.common.java.providers.nativeauth.responses.signin.SignInTokenApiResult
import com.microsoft.identity.common.java.providers.oauth2.OAuth2StrategyParameters
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import org.powermock.core.classloader.annotations.PowerMockIgnore
import org.powermock.core.classloader.annotations.PrepareForTest
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.net.URL
import java.util.UUID

/**
 * These are integration tests using real API responses instead of mocked API responses. This class
 * covers all sign up endpoints.
 * These tests run on the mock API, see: https://native-ux-mock-api.azurewebsites.net/
 */
@RunWith(
    RobolectricTestRunner::class
)
@PowerMockIgnore("javax.net.ssl.*")
@PrepareForTest(DiagnosticContext::class)
@Config(sdk = [Build.VERSION_CODES.O_MR1])
class SignInOAuthStrategyTest {
    private val username = "user@email.com"
    private val password = "verySafePassword"
    private val clientId = "079af063-4ea7-4dcd-91ff-2b24f54621ea"
    private val tokenEndpoint = URL("https://contoso.com/1234/token")
    private val challengeType = "oob password redirect"
    private val userAttributes = mapOf(Pair("city", "Dublin"))
    private val credentialToken = "uY29tL2F1dGhlbnRpY"
    private val grantType = "oob"
    private val oob = "1234"
    private val signInSLT = "12345"

    private val mockConfig = mock<NativeAuthOAuth2Configuration>()
    private val mockStrategyParams = mock<OAuth2StrategyParameters>()

    private lateinit var nativeAuthOAuth2Strategy: NativeAuthOAuth2Strategy

    @Before
    fun setup() {
        whenever(mockConfig.clientId).thenReturn(clientId)
        whenever(mockConfig.tokenEndpoint).thenReturn(ApiConstants.tokenEndpoint)
        whenever(mockConfig.getSignUpStartEndpoint()).thenReturn(ApiConstants.signUpStartRequestUrl)
        whenever(mockConfig.getSignUpChallengeEndpoint()).thenReturn(ApiConstants.signUpChallengeRequestUrl)
        whenever(mockConfig.getSignUpContinueEndpoint()).thenReturn(ApiConstants.signUpContinueRequestUrl)
        whenever(mockConfig.getSignInInitiateEndpoint()).thenReturn(ApiConstants.signInInitiateRequestUrl)
        whenever(mockConfig.getSignInChallengeEndpoint()).thenReturn(ApiConstants.signInChallengeRequestUrl)
        whenever(mockConfig.getSignInTokenEndpoint()).thenReturn(ApiConstants.signInTokenRequestUrl)
        whenever(mockConfig.getResetPasswordStartEndpoint()).thenReturn(ApiConstants.ssprStartRequestUrl)
        whenever(mockConfig.getResetPasswordChallengeEndpoint()).thenReturn(ApiConstants.ssprChallengeRequestUrl)
        whenever(mockConfig.getResetPasswordContinueEndpoint()).thenReturn(ApiConstants.ssprContinueRequestUrl)
        whenever(mockConfig.getResetPasswordSubmitEndpoint()).thenReturn(ApiConstants.ssprSubmitRequestUrl)
        whenever(mockConfig.getResetPasswordPollCompletionEndpoint()).thenReturn(ApiConstants.ssprPollCompletionRequestUrl)
        whenever(mockConfig.challengeType).thenReturn(challengeType)

        nativeAuthOAuth2Strategy = NativeAuthOAuth2Strategy(
            config = mockConfig,
            strategyParameters = mockStrategyParams,
            signUpInteractor = SignUpInteractor(
                httpClient = UrlConnectionHttpClient.getDefaultInstance(),
                nativeAuthRequestProvider = NativeAuthRequestProvider(
                    mockConfig
                ),
                nativeAuthResponseHandler = NativeAuthResponseHandler()
            ),
            signInInteractor = SignInInteractor(
                httpClient = UrlConnectionHttpClient.getDefaultInstance(),
                nativeAuthRequestProvider = NativeAuthRequestProvider(
                    mockConfig
                ),
                nativeAuthResponseHandler = NativeAuthResponseHandler()
            ),
            resetPasswordInteractor = ResetPasswordInteractor(
                httpClient = UrlConnectionHttpClient.getDefaultInstance(),
                nativeAuthRequestProvider = NativeAuthRequestProvider(mockConfig),
                nativeAuthResponseHandler = NativeAuthResponseHandler()
            )
        )
    }

    @Test
    fun testPerformSignInInitiateSuccess() {
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInInitiate,
            correlationId = UUID.randomUUID().toString(),
            responseType = MockApiResponseType.INITIATE_SUCCESS
        )

        val parameters = SignInStartCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .username(username)
            .build()

        val signInInitiateResult = nativeAuthOAuth2Strategy.performSignInInitiate(
            parameters
        )

        Assert.assertTrue(signInInitiateResult is SignInInitiateApiResult.Success)
    }

    @Test
    fun testPerformSignInChallengeSuccess() {
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInChallenge,
            correlationId = UUID.randomUUID().toString(),
            responseType = MockApiResponseType.CHALLENGE_TYPE_REDIRECT
        )

        val signInChallengeResult = nativeAuthOAuth2Strategy.performSignInChallenge(
            credentialToken = "1234"
        )

        Assert.assertTrue(signInChallengeResult is SignInChallengeApiResult.Redirect)
    }

    @Test
    fun testPerformSignInTokenWithPasswordSuccess() {
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInInitiate,
            correlationId = UUID.randomUUID().toString(),
            responseType = MockApiResponseType.INITIATE_SUCCESS
        )

        val parameters = SignInStartUsingPasswordCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .username(username)
            .password(password)
            .build()

        val signInChallengeResult = nativeAuthOAuth2Strategy.performSignInInitiate(
            parameters = parameters
        )

        Assert.assertTrue(signInChallengeResult is SignInInitiateApiResult.Success)
    }

    @Test
    fun testPerformSignInTokenWithOobSuccess() {
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInToken,
            correlationId = UUID.randomUUID().toString(),
            responseType = MockApiResponseType.TOKEN_SUCCESS
        )

        val parameters = mockk<SignInSubmitCodeCommandParameters>()
        every { parameters.getCode() } returns oob
        every { parameters.getCredentialToken() } returns credentialToken

        val signInChallengeResult = nativeAuthOAuth2Strategy.performOOBTokenRequest(
            parameters = parameters
        )

        Assert.assertTrue(signInChallengeResult is SignInTokenApiResult.Success)
        Assert.assertTrue((signInChallengeResult as SignInTokenApiResult.Success).tokenResponse.accessToken.isNotEmpty())
    }

    @Test
    fun testPerformOobTokenWithInvalidOob() {
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInToken,
            correlationId = UUID.randomUUID().toString(),
            responseType = MockApiResponseType.INVALID_OOB_VALUE
        )

        val parameters = mockk<SignInSubmitCodeCommandParameters>()
        every { parameters.getCode() } returns oob
        every { parameters.getCredentialToken() } returns credentialToken

        val signInChallengeResult = nativeAuthOAuth2Strategy.performOOBTokenRequest(
            parameters = parameters
        )

        Assert.assertTrue(signInChallengeResult is SignInTokenApiResult.CodeIncorrect)
    }

    @Test
    fun testPerformSignInInitiateWithChallengeTypeRedirectSuccess() {
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInInitiate,
            correlationId = UUID.randomUUID().toString(),
            responseType = MockApiResponseType.CHALLENGE_TYPE_REDIRECT
        )

        val parameters = SignInStartCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .username(username)
            .build()

        val signInInitiateResult = nativeAuthOAuth2Strategy.performSignInInitiate(
            parameters = parameters
        )
        Assert.assertEquals(signInInitiateResult, SignInInitiateApiResult.Redirect)
    }

    @Test
    fun testPerformSignInChallengeWithChallengeTypeOobSuccess() {
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInChallenge,
            correlationId = UUID.randomUUID().toString(),
            responseType = MockApiResponseType.CHALLENGE_TYPE_OOB
        )
        val signInChallengeResult = nativeAuthOAuth2Strategy.performSignInChallenge(
            credentialToken = credentialToken
        )

        Assert.assertTrue(signInChallengeResult is SignInChallengeApiResult.OOBRequired)
    }

    @Test
    fun testPerformSignInChallengeWithChallengeTypePasswordSuccess() {
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInChallenge,
            correlationId = UUID.randomUUID().toString(),
            responseType = MockApiResponseType.CHALLENGE_TYPE_PASSWORD
        )
        val signInChallengeResult = nativeAuthOAuth2Strategy.performSignInChallenge(
            credentialToken = credentialToken
        )

        Assert.assertTrue(signInChallengeResult is SignInChallengeApiResult.PasswordRequired)
    }

    @Test
    fun testPerformSignInChallengeWithRedirectSuccess() {
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInChallenge,
            correlationId = UUID.randomUUID().toString(),
            responseType = MockApiResponseType.CHALLENGE_TYPE_REDIRECT
        )
        val signInChallengeResult = nativeAuthOAuth2Strategy.performSignInChallenge(
            credentialToken = credentialToken
        )
        Assert.assertEquals(SignInChallengeApiResult.Redirect, signInChallengeResult)
    }

    @Test
    fun testPerformTokenWithInvalidGrantError() {
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInToken,
            correlationId = UUID.randomUUID().toString(),
            responseType = MockApiResponseType.INVALID_GRANT
        )

        val parameters = SignInSubmitPasswordCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .password(password)
            .credentialToken(credentialToken)
            .build()

        val result = nativeAuthOAuth2Strategy.performPasswordTokenRequest(
            parameters = parameters
        )
        Assert.assertTrue(result is SignInTokenApiResult.UnknownError)
    }

    @Test
    fun testPerformPasswordTokenRequestSuccess() {
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInToken,
            correlationId = UUID.randomUUID().toString(),
            responseType = MockApiResponseType.TOKEN_SUCCESS
        )

        val parameters = SignInSubmitPasswordCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .password(password)
            .credentialToken(credentialToken)
            .build()

        val result = nativeAuthOAuth2Strategy.performPasswordTokenRequest(
            parameters = parameters
        )
        Assert.assertTrue(result is SignInTokenApiResult.Success)
    }

    @Test
    fun testPerformPasswordTokenRequestIncorrectPassword() {
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInToken,
            correlationId = UUID.randomUUID().toString(),
            responseType = MockApiResponseType.SIGNIN_INVALID_PASSWORD
        )

        val parameters = SignInSubmitPasswordCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .password(password)
            .credentialToken(credentialToken)
            .build()

        val result = nativeAuthOAuth2Strategy.performPasswordTokenRequest(
            parameters = parameters
        )
        Assert.assertTrue(result is SignInTokenApiResult.InvalidCredentials)
    }

    @Test
    fun testPerformPasswordTokenRequestUserNotFound() {
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInToken,
            correlationId = UUID.randomUUID().toString(),
            responseType = MockApiResponseType.USER_NOT_FOUND
        )

        val parameters = SignInSubmitPasswordCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .password(password)
            .credentialToken(credentialToken)
            .build()

        val result = nativeAuthOAuth2Strategy.performPasswordTokenRequest(
            parameters = parameters
        )
        Assert.assertTrue(result is SignInTokenApiResult.UserNotFound)
    }

    @Test
    fun testPerformSLTTokenRequest() {
        val correlationId = UUID.randomUUID().toString()
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInToken,
            correlationId = correlationId,
            responseType = MockApiResponseType.TOKEN_SUCCESS
        )

        val parameters = SignInWithSLTCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .signInSLT(signInSLT)
            .build()

        val result = nativeAuthOAuth2Strategy.performSLTTokenRequest(
            parameters = parameters
        )
        Assert.assertTrue(result is SignInTokenApiResult.Success)
    }

    @Test
    fun testSignInStartWithPasswordMFARequired() {
        val correlationId = UUID.randomUUID().toString()
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInToken,
            correlationId = correlationId,
            responseType = MockApiResponseType.MFA_REQUIRED
        )

        val parameters = SignInWithSLTCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .signInSLT(signInSLT)
            .build()

        val result = nativeAuthOAuth2Strategy.performSLTTokenRequest(
            parameters = parameters
        )
        Assert.assertTrue(result is SignInTokenApiResult.MFARequired)
    }

    @Test
    fun testPerformSLTTokenRequestUserNotFound() {
        val correlationId = UUID.randomUUID().toString()
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInToken,
            correlationId = correlationId,
            responseType = MockApiResponseType.USER_NOT_FOUND
        )

        val parameters = SignInWithSLTCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .signInSLT(signInSLT)
            .build()

        val result = nativeAuthOAuth2Strategy.performSLTTokenRequest(
            parameters = parameters
        )
        Assert.assertTrue(result is SignInTokenApiResult.UserNotFound)
    }
}
