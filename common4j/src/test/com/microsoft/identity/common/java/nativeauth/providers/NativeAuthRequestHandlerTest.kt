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
package com.microsoft.identity.common.java.nativeauth.providers

import com.microsoft.identity.common.nativeauth.ApiConstants.Companion.signInChallengeRequestUrl
import com.microsoft.identity.common.nativeauth.ApiConstants.Companion.signInInitiateRequestUrl
import com.microsoft.identity.common.nativeauth.ApiConstants.Companion.signInTokenRequestUrl
import com.microsoft.identity.common.nativeauth.ApiConstants.Companion.signUpChallengeRequestUrl
import com.microsoft.identity.common.nativeauth.ApiConstants.Companion.signUpContinueRequestUrl
import com.microsoft.identity.common.nativeauth.ApiConstants.Companion.signUpStartRequestUrl
import com.microsoft.identity.common.nativeauth.ApiConstants.Companion.ssprChallengeRequestUrl
import com.microsoft.identity.common.nativeauth.ApiConstants.Companion.ssprContinueRequestUrl
import com.microsoft.identity.common.nativeauth.ApiConstants.Companion.ssprPollCompletionRequestUrl
import com.microsoft.identity.common.nativeauth.ApiConstants.Companion.ssprStartRequestUrl
import com.microsoft.identity.common.nativeauth.ApiConstants.Companion.ssprSubmitRequestUrl
import com.microsoft.identity.common.java.nativeauth.commands.parameters.ResetPasswordStartCommandParameters
import com.microsoft.identity.common.java.nativeauth.commands.parameters.ResetPasswordSubmitCodeCommandParameters
import com.microsoft.identity.common.java.nativeauth.commands.parameters.ResetPasswordSubmitNewPasswordCommandParameters
import com.microsoft.identity.common.java.nativeauth.commands.parameters.SignInStartCommandParameters
import com.microsoft.identity.common.java.nativeauth.commands.parameters.SignInStartUsingPasswordCommandParameters
import com.microsoft.identity.common.java.nativeauth.commands.parameters.SignInSubmitCodeCommandParameters
import com.microsoft.identity.common.java.nativeauth.commands.parameters.SignInSubmitPasswordCommandParameters
import com.microsoft.identity.common.java.nativeauth.commands.parameters.SignInWithContinuationTokenCommandParameters
import com.microsoft.identity.common.java.nativeauth.commands.parameters.SignUpStartCommandParameters
import com.microsoft.identity.common.java.nativeauth.commands.parameters.SignUpStartUsingPasswordCommandParameters
import com.microsoft.identity.common.java.nativeauth.commands.parameters.SignUpSubmitCodeCommandParameters
import com.microsoft.identity.common.java.nativeauth.commands.parameters.SignUpSubmitPasswordCommandParameters
import com.microsoft.identity.common.java.nativeauth.commands.parameters.SignUpSubmitUserAttributesCommandParameters
import com.microsoft.identity.common.java.exception.ClientException
import com.microsoft.identity.common.java.interfaces.PlatformComponents
import com.microsoft.identity.common.java.nativeauth.providers.requests.NativeAuthRequest.Companion.toJsonString
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Test
import org.mockito.kotlin.mock
import java.net.URL

class NativeAuthRequestHandlerTest {
    private val username = "user@email.com"
    private val password = "verySafePassword".toCharArray()
    private val clientId = "1234"
    private val tenant = "samtoso.onmicrosoft.com"
    private val tokenEndpoint = URL("https://contoso.com/1234/token")
    private val challengeType = "oob redirect"
    private val userAttributes = mapOf("city" to "Dublin")
    private val emptyUserAttributes = emptyMap<String, String>()
    private val oobGrantType = "oob"
    private val passwordGrantType = "password"
    private val oobCode = "123456"
    private val passwordResetToken = "123456"
    private val passwordSubmitToken = "123456"
    private val continuationToken = "1234"
    private val emptyString = ""
    private val emptyPassword = "".toCharArray()
    private val credentialToken = "uY29tL2F1dGhlbnRpY"
    private val grantType = NativeAuthConstants.GrantType.OOB
    private val signupToken = "ifQ"

    private val mockConfig = mockk<NativeAuthOAuth2Configuration> {
        every { getSignUpStartEndpoint() } returns signUpStartRequestUrl
        every { getSignUpChallengeEndpoint() } returns signUpChallengeRequestUrl
        every { getSignUpContinueEndpoint() } returns signUpContinueRequestUrl
        every { getSignInInitiateEndpoint() } returns signInInitiateRequestUrl
        every { getSignInChallengeEndpoint() } returns signInChallengeRequestUrl
        every { getSignInTokenEndpoint() } returns signInTokenRequestUrl
        every { getResetPasswordStartEndpoint() } returns ssprStartRequestUrl
        every { getResetPasswordChallengeEndpoint() } returns ssprChallengeRequestUrl
        every { getResetPasswordContinueEndpoint() } returns ssprContinueRequestUrl
        every { getResetPasswordSubmitEndpoint() } returns ssprSubmitRequestUrl
        every { getResetPasswordPollCompletionEndpoint() } returns ssprPollCompletionRequestUrl
        every { challengeType } returns this@NativeAuthRequestHandlerTest.challengeType
        every { clientId } returns this@NativeAuthRequestHandlerTest.clientId
        every { useMockApiForNativeAuth } returns true
    }

    private val nativeAuthRequestProvider =
        NativeAuthRequestProvider(
            config = mockConfig
        )

    // signup start tests
    @Test(expected = ClientException::class)
    fun testSignUpStartWithEmptyUsernameShouldThrowException() {
        val commandParameters = SignUpStartCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .username(emptyString)
            .clientId(clientId)
            .build()

        nativeAuthRequestProvider.createSignUpStartRequest(
            commandParameters = commandParameters
        )
    }

    @Test(expected = ClientException::class)
    fun testSignUpStartWithEmptyPasswordShouldThrowException() {
        val commandParameters = SignUpStartUsingPasswordCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .username(username)
            .password(emptyPassword)
            .clientId(clientId)
            .build()

        nativeAuthRequestProvider.createSignUpUsingPasswordStartRequest(
            commandParameters = commandParameters
        )
    }

    @Test(expected = ClientException::class)
    fun testSignUpStartWithEmptyClientIdShouldThrowException() {
        every { mockConfig.clientId } returns emptyString

        val commandParameters = SignUpStartCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .username(username)
            .clientId(emptyString)
            .build()

        nativeAuthRequestProvider.createSignUpStartRequest(
            commandParameters = commandParameters
        )
    }

    @Test(expected = ClientException::class)
    fun testSignUpStartWithEmptyChallengeTypesShouldThrowException() {
        every { mockConfig.challengeType } returns emptyString

        val commandParameters = SignUpStartCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .username(username)
            .clientId(clientId)
            .build()

        nativeAuthRequestProvider.createSignUpStartRequest(
            commandParameters = commandParameters
        )
    }

    @Test
    fun testSignUpStartSuccess() {
        val commandParameters = SignUpStartCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .username(username)
            .clientId(clientId)
            .userAttributes(userAttributes)
            .build()

        val result = nativeAuthRequestProvider.createSignUpStartRequest(
            commandParameters = commandParameters
        )

        assertEquals(username, result.parameters.username)
        assertEquals(clientId, result.parameters.clientId)
        assertEquals(challengeType, result.parameters.challengeType)
        assertEquals(signUpStartRequestUrl, result.requestUrl)
        assertEquals(userAttributes.toJsonString(userAttributes), result.parameters.attributes)
    }

    @Test
    fun testSignUpStartWithPasswordSuccess() {
        val commandParameters = SignUpStartUsingPasswordCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .username(username)
            .password(password)
            .clientId(clientId)
            .userAttributes(userAttributes)
            .build()

        val result = nativeAuthRequestProvider.createSignUpUsingPasswordStartRequest(
            commandParameters = commandParameters
        )

        assertEquals(username, result.parameters.username)
        assertEquals(clientId, result.parameters.clientId)
        assertEquals(challengeType, result.parameters.challengeType)
        assertEquals(signUpStartRequestUrl, result.requestUrl)
        assertEquals(userAttributes.toJsonString(userAttributes), result.parameters.attributes)
    }

    @Test
    fun testSignUpSubmitCodeSuccess() {
        val commandParameters = SignUpSubmitCodeCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .signupToken(signupToken)
            .code(oobCode)
            .clientId(clientId)
            .build()

        val result = nativeAuthRequestProvider.createSignUpSubmitCodeRequest(
            commandParameters = commandParameters
        )

        assertEquals(oobCode, result.parameters.oob)
        assertEquals(signupToken, result.parameters.signUpToken)
        assertEquals(oobGrantType, result.parameters.grantType)
        assertEquals(signUpContinueRequestUrl, result.requestUrl)
    }

    @Test
    fun testSignUpSubmitPasswordSuccess() {
        val commandParameters = SignUpSubmitPasswordCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .signupToken(signupToken)
            .password(password)
            .clientId(clientId)
            .build()

        val result = nativeAuthRequestProvider.createSignUpSubmitPasswordRequest(
            commandParameters = commandParameters
        )

        assertEquals(password.toString(), result.parameters.password.toString())
        assertEquals(signupToken, result.parameters.signUpToken)
        assertEquals(passwordGrantType, result.parameters.grantType)
        assertEquals(signUpContinueRequestUrl, result.requestUrl)
    }

    @Test
    fun testSignUpSubmitUserAttributesSuccess() {
        val commandParameters = SignUpSubmitUserAttributesCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .signupToken(signupToken)
            .userAttributes(userAttributes)
            .clientId(clientId)
            .build()

        val result = nativeAuthRequestProvider.createSignUpSubmitUserAttributesRequest(
            commandParameters = commandParameters
        )

        assertEquals(userAttributes.toJsonString(userAttributes), result.parameters.attributes)
        assertEquals(signupToken, result.parameters.signUpToken)
        assertEquals(signUpContinueRequestUrl, result.requestUrl)
    }

    @Test(expected = ClientException::class)
    fun testSignUpSubmitEmptyUserAttributesShouldThrowExceptionSuccess() {
        val commandParameters = SignUpSubmitUserAttributesCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .signupToken(signupToken)
            .userAttributes(emptyUserAttributes)
            .clientId(clientId)
            .build()

        nativeAuthRequestProvider.createSignUpSubmitUserAttributesRequest(
            commandParameters = commandParameters
        )
    }

    @Test(expected = ClientException::class)
    fun testSignUpSubmitEmptyPasswordShouldThrowExceptionSuccess() {
        val commandParameters = SignUpSubmitPasswordCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .signupToken(signupToken)
            .password(emptyPassword)
            .clientId(clientId)
            .build()

        nativeAuthRequestProvider.createSignUpSubmitPasswordRequest(
            commandParameters = commandParameters
        )
    }

    @Test(expected = ClientException::class)
    fun testSignUpSubmitEmptyCodedShouldThrowExceptionSuccess() {
        val commandParameters = SignUpSubmitCodeCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .signupToken(signupToken)
            .code(emptyString)
            .clientId(clientId)
            .build()

        nativeAuthRequestProvider.createSignUpSubmitCodeRequest(
            commandParameters = commandParameters
        )
    }

    // signup challenge tests
    @Test
    fun testSignUpChallengeSuccess() {
        nativeAuthRequestProvider.createSignUpChallengeRequest(
            signUpToken = signupToken
        )

        val result = nativeAuthRequestProvider.createSignUpChallengeRequest(
            signUpToken = signupToken
        )

        assertEquals(challengeType, result.parameters.challengeType)
        assertEquals(signupToken, result.parameters.signUpToken)
        assertEquals(signUpChallengeRequestUrl, result.requestUrl)
    }

    @Test(expected = ClientException::class)
    fun testSignUpChallengeWithEmptySignUpTokenShouldThrowException() {
        nativeAuthRequestProvider.createSignUpChallengeRequest(
            signUpToken = emptyString
        )
    }

    @Test(expected = ClientException::class)
    fun testSignUpChallengeWithEmptyClientIdShouldThrowException() {
        every { mockConfig.clientId } returns emptyString

        nativeAuthRequestProvider.createSignUpChallengeRequest(
            signUpToken = signupToken
        )
    }

    @Test(expected = ClientException::class)
    fun testSignUpChallengeWithEmptyChallengeTypesShouldThrowException() {
        every { mockConfig.challengeType } returns emptyString

        nativeAuthRequestProvider.createSignUpChallengeRequest(
            signUpToken = signupToken
        )
    }

    // signin tests
    @Test(expected = ClientException::class)
    fun testSignInInitiateWithEmptyUsernameShouldThrowException() {
        val commandParameters = SignInStartCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .username(emptyString)
            .build()

        nativeAuthRequestProvider.createSignInInitiateRequest(
            parameters = commandParameters
        )
    }

    @Test(expected = ClientException::class)
    fun testSignInInitiateWithEmptyClientIdShouldThrowException() {
        every { mockConfig.clientId } returns emptyString

        val commandParameters = SignInStartCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .username(username)
            .build()

        nativeAuthRequestProvider.createSignInInitiateRequest(
            parameters = commandParameters
        )
    }

    @Test(expected = ClientException::class)
    fun testSignInInitiateWithEmptyChallengeTypesShouldThrowException() {
        every { mockConfig.challengeType } returns emptyString

        val commandParameters = SignInStartCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .username(username)
            .build()

        nativeAuthRequestProvider.createSignInInitiateRequest(
            parameters = commandParameters
        )
    }

    @Test
    fun testSignInInitiateSuccess() {
        val commandParameters = SignInStartCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .username(username)
            .build()

        val result = nativeAuthRequestProvider.createSignInInitiateRequest(
            parameters = commandParameters
        )

        assertEquals(username, result.parameters.username)
        assertEquals(clientId, result.parameters.clientId)
        assertEquals(challengeType, result.parameters.challengeType)
        assertEquals(signInInitiateRequestUrl, result.requestUrl)
    }

    @Test(expected = ClientException::class)
    fun testSignInChallengeWithEmptyClientIdShouldThrowException() {
        every { mockConfig.clientId } returns emptyString

        nativeAuthRequestProvider.createSignInChallengeRequest(
            credentialToken = credentialToken
        )
    }

    @Test(expected = ClientException::class)
    fun testSignInChallengeWithEmptyChallengeTypeShouldThrowException() {
        every { mockConfig.challengeType } returns emptyString

        nativeAuthRequestProvider.createSignInChallengeRequest(
            credentialToken = credentialToken
        )
    }

    @Test(expected = ClientException::class)
    fun testSignInChallengeWithEmptyCredentialTokenShouldThrowException() {
        nativeAuthRequestProvider.createSignInChallengeRequest(
            credentialToken = emptyString
        )
    }

    @Test
    fun testSignInChallengeSuccess() {
        val result = nativeAuthRequestProvider.createSignInChallengeRequest(
            credentialToken = credentialToken
        )

        assertEquals(clientId, result.parameters.clientId)
        assertEquals(credentialToken, result.parameters.credentialToken)
        assertEquals(signInChallengeRequestUrl, result.requestUrl)
    }

    @Test(expected = ClientException::class)
    fun testSignInInitiateWithPasswordCommandParametersWithEmptyClientIdShouldThrowException() {
        every { mockConfig.clientId } returns emptyString

        val commandParameters = SignInStartUsingPasswordCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .username(username)
            .password(password)
            .build()

        nativeAuthRequestProvider.createSignInInitiateRequest(
            parameters = commandParameters
        )
    }

    @Test(expected = ClientException::class)
    fun testSignInInitiateWithPasswordCommandParametersWithEmptyChallengeTypeShouldThrowException() {
        every { mockConfig.challengeType } returns emptyString

        val commandParameters = SignInStartUsingPasswordCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .username(username)
            .password(password)
            .build()

        nativeAuthRequestProvider.createSignInInitiateRequest(
            parameters = commandParameters
        )
    }

    @Test(expected = ClientException::class)
    fun testSignInInitiateWithPasswordCommandParametersWithEmptyUsernameShouldThrowException() {
        val commandParameters = SignInStartUsingPasswordCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .username(emptyString)
            .password(password)
            .build()

        nativeAuthRequestProvider.createSignInInitiateRequest(
            parameters = commandParameters
        )
    }

    // The password is not sent to /initiate (but to /token), so no password check (and fail) has
    // to be done here.
    @Test
    fun testSignInInitiateWithPasswordCommandParametersWithEmptyPasswordShouldNotThrowException() {
        val commandParameters = SignInStartUsingPasswordCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .username(username)
            .password(emptyPassword)
            .build()

        nativeAuthRequestProvider.createSignInInitiateRequest(
            parameters = commandParameters
        )
    }

    @Test
    fun testSignInTokenWithContinuationTokenSuccess() {
        val commandParameters = SignInWithContinuationTokenCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .continuationToken(continuationToken)
            .username(username)
            .build()

        nativeAuthRequestProvider.createContinuationTokenTokenRequest(
            parameters = commandParameters
        )
    }

    @Test(expected = ClientException::class)
    fun testSignInTokenWithEmptyContinuationTokenShouldThrowException() {
        val commandParameters = SignInWithContinuationTokenCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .continuationToken(emptyString)
            .username(username)
            .build()

        nativeAuthRequestProvider.createContinuationTokenTokenRequest(
            parameters = commandParameters
        )
    }

    @Test(expected = ClientException::class)
    fun testSignInTokenWithEmptyUsernameShouldThrowException() {
        val commandParameters = SignInWithContinuationTokenCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .continuationToken(continuationToken)
            .username(emptyString)
            .build()

        nativeAuthRequestProvider.createContinuationTokenTokenRequest(
            parameters = commandParameters
        )
    }

    @Test(expected = ClientException::class)
    fun testSignInTokenWithEmptyCredentialTokenShouldThrowException() {
        val commandParameters = SignInSubmitCodeCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .code(oobCode)
            .credentialToken(emptyString)
            .build()

        nativeAuthRequestProvider.createOOBTokenRequest(
            parameters = commandParameters
        )
    }

    @Test(expected = ClientException::class)
    fun testSignInTokenWithEmptyOOBShouldThrowException() {
        val commandParameters = SignInSubmitCodeCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .code(emptyString)
            .credentialToken(credentialToken)
            .build()

        nativeAuthRequestProvider.createOOBTokenRequest(
            parameters = commandParameters
        )
    }

    @Test(expected = ClientException::class)
    fun testPasswordTokenRequestWithEmptyPasswordShouldThrowException() {
        val commandParameters = SignInSubmitPasswordCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .password(emptyPassword)
            .credentialToken(credentialToken)
            .build()

        nativeAuthRequestProvider.createPasswordTokenRequest(
            parameters = commandParameters
        )
    }

    @Test(expected = ClientException::class)
    fun testPasswordTokenRequestWithEmptyCredentialTokenShouldThrowException() {
        val commandParameters = SignInSubmitPasswordCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .password(password)
            .credentialToken(emptyString)
            .build()

        nativeAuthRequestProvider.createPasswordTokenRequest(
            parameters = commandParameters
        )
    }

    @Test
    fun testPasswordTokenRequestSuccess() {
        val commandParameters = SignInSubmitPasswordCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .password(password)
            .credentialToken(credentialToken)
            .build()

        nativeAuthRequestProvider.createPasswordTokenRequest(
            parameters = commandParameters
        )
    }

    @Test(expected = ClientException::class)
    fun testSignUpContinueWithEmptySignUpTokenThrowException() {
        val commandParameters = SignUpSubmitCodeCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .signupToken(emptyString)
            .code(oobCode)
            .build()

        nativeAuthRequestProvider.createSignUpSubmitCodeRequest(
            commandParameters = commandParameters
        )
    }

    @Test(expected = ClientException::class)
    fun testSignUpContinueWithEmptyClientIdShouldThrowException() {
        every { mockConfig.clientId } returns emptyString

        val commandParameters = SignUpSubmitCodeCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .signupToken(signupToken)
            .code(oobCode)
            .build()

        nativeAuthRequestProvider.createSignUpSubmitCodeRequest(
            commandParameters = commandParameters
        )
    }

    // sspr start tests
    @Test(expected = ClientException::class)
    fun testResetPasswordStartWithEmptyUsernameShouldThrowException() {
        val commandParameters = ResetPasswordStartCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .username(emptyString)
            .build()

        nativeAuthRequestProvider.createResetPasswordStartRequest(
            parameters = commandParameters
        )
    }

    @Test(expected = ClientException::class)
    fun testResetPasswordStartWithEmptyClientIdShouldThrowException() {
        every { mockConfig.clientId } returns emptyString

        val commandParameters = ResetPasswordStartCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .username(username)
            .build()

        nativeAuthRequestProvider.createResetPasswordStartRequest(
            parameters = commandParameters
        )
    }

    @Test(expected = ClientException::class)
    fun testResetPasswordStartWithEmptyChallengeTypeShouldThrowException() {
        every { mockConfig.challengeType } returns emptyString

        val commandParameters = ResetPasswordStartCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .username(username)
            .build()

        nativeAuthRequestProvider.createResetPasswordStartRequest(
            parameters = commandParameters
        )
    }

    @Test
    fun testResetPasswordStartSuccess() {
        val commandParameters = ResetPasswordStartCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .username(username)
            .build()

        nativeAuthRequestProvider.createResetPasswordStartRequest(
            parameters = commandParameters
        )
    }

    // ResetPassword challenge tests
    @Test(expected = ClientException::class)
    fun testResetPasswordChallengeWithEmptyClientIdShouldThrowException() {
        every { mockConfig.clientId } returns emptyString

        nativeAuthRequestProvider.createResetPasswordChallengeRequest(
            passwordResetToken = passwordResetToken
        )
    }

    @Test(expected = ClientException::class)
    fun testResetPasswordChallengeWithEmptyPasswordResetTokenShouldThrowException() {
        nativeAuthRequestProvider.createResetPasswordChallengeRequest(
            passwordResetToken = emptyString
        )
    }

    @Test
    fun testResetPasswordChallengeSuccess() {
        nativeAuthRequestProvider.createResetPasswordChallengeRequest(
            passwordResetToken = passwordResetToken
        )
    }

    // ResetPassword continue tests
    @Test(expected = ClientException::class)
    fun testResetPasswordContinueWithEmptyClientIdShouldThrowException() {
        every { mockConfig.clientId } returns emptyString

        val commandParameters = ResetPasswordSubmitCodeCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .code(oobCode)
            .passwordResetToken(passwordResetToken)
            .build()

        nativeAuthRequestProvider.createResetPasswordContinueRequest(
            parameters = commandParameters
        )
    }

    @Test(expected = ClientException::class)
    fun testResetPasswordContinueWithEmptyPasswordResetTokenShouldThrowException() {
        val commandParameters = ResetPasswordSubmitCodeCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .code(oobCode)
            .passwordResetToken(emptyString)
            .build()

        nativeAuthRequestProvider.createResetPasswordContinueRequest(
            parameters = commandParameters
        )
    }

    @Test(expected = ClientException::class)
    fun testResetPasswordContinueWithEmptyOobCodeShouldThrowException() {
        val commandParameters = ResetPasswordSubmitCodeCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .code(emptyString)
            .passwordResetToken(passwordResetToken)
            .build()

        nativeAuthRequestProvider.createResetPasswordContinueRequest(
            parameters = commandParameters
        )
    }

    @Test
    fun testResetPasswordContinueSucces() {
        val commandParameters = ResetPasswordSubmitCodeCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .code(oobCode)
            .passwordResetToken(passwordResetToken)
            .build()

        nativeAuthRequestProvider.createResetPasswordContinueRequest(
            parameters = commandParameters
        )
    }

    // ResetPassword submit tests
    @Test(expected = ClientException::class)
    fun testResetPasswordSubmitWithEmptyClientIdShouldThrowException() {
        every { mockConfig.clientId } returns emptyString

        val commandParameters = ResetPasswordSubmitNewPasswordCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .passwordSubmitToken(passwordSubmitToken)
            .newPassword(password)
            .build()

        nativeAuthRequestProvider.createResetPasswordSubmitRequest(
            commandParameters = commandParameters
        )
    }

    @Test(expected = ClientException::class)
    fun testResetPasswordSubmitWithEmptyPasswordShouldThrowException() {
        val commandParameters = ResetPasswordSubmitNewPasswordCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .passwordSubmitToken(passwordSubmitToken)
            .newPassword(emptyPassword)
            .build()

        nativeAuthRequestProvider.createResetPasswordSubmitRequest(
            commandParameters = commandParameters
        )
    }

    @Test(expected = ClientException::class)
    fun testResetPasswordSubmitWithEmptyPasswordSubmitTokenShouldThrowException() {
        val commandParameters = ResetPasswordSubmitNewPasswordCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .passwordSubmitToken(emptyString)
            .newPassword(password)
            .build()

        nativeAuthRequestProvider.createResetPasswordSubmitRequest(
            commandParameters = commandParameters
        )
    }

    @Test
    fun testResetPasswordSubmitSuccess() {
        val commandParameters = ResetPasswordSubmitNewPasswordCommandParameters.builder()
            .platformComponents(mock<PlatformComponents>())
            .passwordSubmitToken(passwordSubmitToken)
            .newPassword(password)
            .build()

        nativeAuthRequestProvider.createResetPasswordSubmitRequest(
            commandParameters = commandParameters
        )
    }

    // ResetPassword completion poll tests
    @Test(expected = ClientException::class)
    fun testResetPasswordPollCompletionWithEmptyClientIdShouldThrowException() {
        every { mockConfig.clientId } returns emptyString

        nativeAuthRequestProvider.createResetPasswordPollCompletionRequest(
            passwordResetToken = passwordResetToken
        )
    }

    @Test(expected = ClientException::class)
    fun testResetPasswordPollCompletionWithEmptyPasswordSubmitTokenShouldThrowException() {
        nativeAuthRequestProvider.createResetPasswordPollCompletionRequest(
            passwordResetToken = emptyString
        )
    }

    @Test
    fun testResetPasswordPollCompletionSuccess() {
        nativeAuthRequestProvider.createResetPasswordPollCompletionRequest(
            passwordResetToken = passwordResetToken
        )
    }
}
