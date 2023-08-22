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
package com.microsoft.identity.common.internal.controllers

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.microsoft.identity.common.components.AndroidPlatformComponentsFactory
import com.microsoft.identity.common.internal.providers.microsoft.nativeauth.utils.MockApiEndpointType
import com.microsoft.identity.common.internal.providers.microsoft.nativeauth.utils.MockApiResponseType
import com.microsoft.identity.common.internal.providers.microsoft.nativeauth.utils.MockApiUtils
import com.microsoft.identity.common.internal.util.capture
import com.microsoft.identity.common.java.AuthenticationConstants
import com.microsoft.identity.common.java.authorities.NativeAuthCIAMAuthority
import com.microsoft.identity.common.java.authscheme.AuthenticationSchemeFactory
import com.microsoft.identity.common.java.cache.MsalOAuth2TokenCache
import com.microsoft.identity.common.java.commands.parameters.RemoveAccountCommandParameters
import com.microsoft.identity.common.java.commands.parameters.nativeauth.ResetPasswordResendCodeCommandParameters
import com.microsoft.identity.common.java.commands.parameters.nativeauth.ResetPasswordStartCommandParameters
import com.microsoft.identity.common.java.commands.parameters.nativeauth.ResetPasswordSubmitCodeCommandParameters
import com.microsoft.identity.common.java.commands.parameters.nativeauth.ResetPasswordSubmitNewPasswordCommandParameters
import com.microsoft.identity.common.java.commands.parameters.nativeauth.SignInResendCodeCommandParameters
import com.microsoft.identity.common.java.commands.parameters.nativeauth.SignInStartCommandParameters
import com.microsoft.identity.common.java.commands.parameters.nativeauth.SignInStartUsingPasswordCommandParameters
import com.microsoft.identity.common.java.commands.parameters.nativeauth.SignInSubmitCodeCommandParameters
import com.microsoft.identity.common.java.commands.parameters.nativeauth.SignInSubmitPasswordCommandParameters
import com.microsoft.identity.common.java.commands.parameters.nativeauth.SignInWithSLTCommandParameters
import com.microsoft.identity.common.java.commands.parameters.nativeauth.SignUpResendCodeCommandParameters
import com.microsoft.identity.common.java.commands.parameters.nativeauth.SignUpStartCommandParameters
import com.microsoft.identity.common.java.commands.parameters.nativeauth.SignUpStartUsingPasswordCommandParameters
import com.microsoft.identity.common.java.commands.parameters.nativeauth.SignUpSubmitCodeCommandParameters
import com.microsoft.identity.common.java.commands.parameters.nativeauth.SignUpSubmitPasswordCommandParameters
import com.microsoft.identity.common.java.commands.parameters.nativeauth.SignUpSubmitUserAttributesCommandParameters
import com.microsoft.identity.common.java.controllers.results.ICommandResult
import com.microsoft.identity.common.java.controllers.results.ResetPasswordCommandResult
import com.microsoft.identity.common.java.controllers.results.SignInCommandResult
import com.microsoft.identity.common.java.controllers.results.SignUpCommandResult
import com.microsoft.identity.common.java.dto.AccountRecord
import com.microsoft.identity.common.java.interfaces.IPlatformComponents
import com.microsoft.identity.common.java.providers.nativeauth.NativeAuthOAuth2Strategy
import com.microsoft.identity.common.java.providers.nativeauth.responses.signin.SignInInitiateApiResult
import com.microsoft.identity.common.java.request.SdkType
import com.microsoft.identity.common.java.util.BrokerProtocolVersionUtil
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.ArgumentCaptor
import org.mockito.Captor
import org.mockito.Mockito.spy
import org.mockito.Mockito.verify
import org.mockito.MockitoAnnotations
import org.mockito.junit.MockitoJUnit
import org.mockito.junit.MockitoRule
import org.robolectric.RobolectricTestRunner
import java.util.UUID

/**
 * Tests for [com.microsoft.identity.common.internal.controllers.NativeAuthController].
 */
@RunWith(RobolectricTestRunner::class)
class NativeAuthControllerTest {
    private val code = "12345"
    private val credentialToken = "sk490fj8a83n*@f-1"
    private val username = "user@email.com"
    private val password = "verySafePassword"
    private val defaultScopes: List<String> = AuthenticationConstants.DEFAULT_SCOPES.toList()
    private val scopes: List<String> = listOf("scope1", "scope2", "scope3")
    private val passwordResetToken = "sk490fj8a83n*@f-2"
    private val passwordSubmitToken = "sk490fj8a83n*@f-3"
    private val invalidGrantError = "invalid_grant"
    private val credentialRequiredError = "credential_required"
    private val signInSLT = "1234"
    private val newPassword = "newPassword"
    private val clientId = "079af063-4ea7-4dcd-91ff-2b24f54621ea"
    private val authorityUrl = "https://msidlabciam1.ciamlogin.com/msidlabciam1.onmicrosoft.com"
    private val signUpToken = "ifQ"
    private val userAttributes = mapOf("city" to "dublin")

    private lateinit var platformComponents: IPlatformComponents
    private lateinit var context: Context

    private val controller = spy(NativeAuthController())
    private val localController = LocalMSALController()

    @Captor
    lateinit var initiateApiResultCaptor: ArgumentCaptor<SignInInitiateApiResult>
    @Captor
    lateinit var signInStartUsingPasswordCommandParametersWithScopesCaptor: ArgumentCaptor<SignInStartUsingPasswordCommandParameters>
    @Captor
    lateinit var signInSubmitPasswordCommandParametersWithScopesCaptor: ArgumentCaptor<SignInSubmitPasswordCommandParameters>
    @Captor
    lateinit var signInWithSLTCommandParametersWithScopesCaptor: ArgumentCaptor<SignInWithSLTCommandParameters>
    @Captor
    lateinit var signUpStartUsingPasswordCommandParametersCaptor: ArgumentCaptor<SignUpStartUsingPasswordCommandParameters>
    @Captor
    lateinit var signUpSubmitUserAttributesCommandParametersCaptor: ArgumentCaptor<SignUpSubmitUserAttributesCommandParameters>
    @Captor
    lateinit var signUpStartCommandParametersCaptor: ArgumentCaptor<SignUpStartCommandParameters>
    @Captor
    lateinit var oAuth2StrategyCaptor: ArgumentCaptor<NativeAuthOAuth2Strategy>
    @Captor
    lateinit var usePasswordCaptor: ArgumentCaptor<Boolean>

    @get:Rule
    var rule: MockitoRule = MockitoJUnit.rule()

    @Before
    fun setup() {
        MockitoAnnotations.initMocks(this)
        context = ApplicationProvider.getApplicationContext()
        platformComponents = AndroidPlatformComponentsFactory.createFromContext(
            context
        )
    }

    // region Sign In
    @Test
    fun testSignInStartWithPasswordSuccess() {
        val correlationId = UUID.randomUUID().toString()
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInInitiate,
            correlationId = correlationId,
            responseType = MockApiResponseType.INITIATE_SUCCESS
        )
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInChallenge,
            correlationId = correlationId,
            responseType = MockApiResponseType.CHALLENGE_TYPE_PASSWORD
        )
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInToken,
            correlationId = correlationId,
            responseType = MockApiResponseType.TOKEN_SUCCESS
        )

        val parameters = createSignInStartWithPasswordCommandParameters()
        val result = controller.signInStart(parameters)
        assert(result is SignInCommandResult.Complete)
    }

    @Test
    fun testSignInStartWithPasswordAssertScopes() {
        val correlationId = UUID.randomUUID().toString()
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInInitiate,
            correlationId = correlationId,
            responseType = MockApiResponseType.INITIATE_SUCCESS
        )
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInChallenge,
            correlationId = correlationId,
            responseType = MockApiResponseType.CHALLENGE_TYPE_PASSWORD
        )
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInToken,
            correlationId = correlationId,
            responseType = MockApiResponseType.TOKEN_SUCCESS
        )

        val parameters = createSignInStartWithPasswordCommandParameters()
        val result = controller.signInStart(parameters)

        verify(controller).processSignInInitiateApiResult(
            capture(initiateApiResultCaptor),
            capture(signInStartUsingPasswordCommandParametersWithScopesCaptor),
            capture(oAuth2StrategyCaptor),
            capture(usePasswordCaptor)
        )

        val scopesToCheck = scopes + defaultScopes
        assertTrue(usePasswordCaptor.value)
        assertEquals(scopesToCheck, signInStartUsingPasswordCommandParametersWithScopesCaptor.value?.scopes)
        assert(result is SignInCommandResult.Complete)
    }

    @Test
    fun testSignInStartWithPasswordPasswordIncorrect() {
        val correlationId = UUID.randomUUID().toString()
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInInitiate,
            correlationId = correlationId,
            responseType = MockApiResponseType.INITIATE_SUCCESS
        )
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInChallenge,
            correlationId = correlationId,
            responseType = MockApiResponseType.CHALLENGE_TYPE_PASSWORD
        )
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInToken,
            correlationId = correlationId,
            responseType = MockApiResponseType.SIGNIN_INVALID_PASSWORD
        )

        val parameters = createSignInStartWithPasswordCommandParameters()
        val result = controller.signInStart(parameters)
        assert(result is SignInCommandResult.InvalidCredentials)
    }

    @Test
    fun testSignInStartWithPasswordUserNotFound() {
        val correlationId = UUID.randomUUID().toString()
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInInitiate,
            correlationId = correlationId,
            responseType = MockApiResponseType.USER_NOT_FOUND
        )

        val parameters = createSignInStartWithPasswordCommandParameters()
        val result = controller.signInStart(parameters)
        assert(result is SignInCommandResult.UserNotFound)
    }

    @Test
    fun testSignInStartWithPasswordCodeRequired() {
        val correlationId = UUID.randomUUID().toString()
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInInitiate,
            correlationId = correlationId,
            responseType = MockApiResponseType.INITIATE_SUCCESS
        )
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInChallenge,
            correlationId = correlationId,
            responseType = MockApiResponseType.CHALLENGE_TYPE_OOB
        )

        val parameters = createSignInStartWithPasswordCommandParameters()
        val result = controller.signInStart(parameters)
        assert(result is SignInCommandResult.CodeRequired)
    }

    @Test
    fun testSignInStartWithPasswordMFARequired() {
        val correlationId = UUID.randomUUID().toString()
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInToken,
            correlationId = correlationId,
            responseType = MockApiResponseType.MFA_REQUIRED
        )

        val parameters = createSignInStartWithPasswordCommandParameters()
        val result = controller.signInStart(parameters)
        assert(result is ICommandResult.Redirect)
    }

    @Test
    fun testSignInStartWithEmailUserNotFound() {
        val correlationId = UUID.randomUUID().toString()
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInInitiate,
            correlationId = correlationId,
            responseType = MockApiResponseType.USER_NOT_FOUND
        )

        val parameters = createSignInStartCommandParameters()
        val result = controller.signInStart(parameters)
        assert(result is SignInCommandResult.UserNotFound)
    }

    @Test
    fun testSignInStartWithEmailCodeRequired() {
        val correlationId = UUID.randomUUID().toString()
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInInitiate,
            correlationId = correlationId,
            responseType = MockApiResponseType.INITIATE_SUCCESS
        )
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInChallenge,
            correlationId = correlationId,
            responseType = MockApiResponseType.CHALLENGE_TYPE_OOB
        )

        val parameters = createSignInStartCommandParameters()
        val result = controller.signInStart(parameters)
        assert(result is SignInCommandResult.CodeRequired)
    }

    @Test
    fun testSignInSubmitCodeWithSuccess() {
        val correlationId = UUID.randomUUID().toString()
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInToken,
            correlationId = correlationId,
            responseType = MockApiResponseType.TOKEN_SUCCESS
        )

        val parameters = createSignInSubmitCodeCommandParameters()
        val result = controller.signInSubmitCode(parameters)
        assert(result is SignInCommandResult.Complete)
    }

    @Test
    fun testSignInSubmitCodeWithInvalidCode() {
        val correlationId = UUID.randomUUID().toString()
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInToken,
            correlationId = correlationId,
            responseType = MockApiResponseType.INVALID_OOB_VALUE
        )

        val parameters = createSignInSubmitCodeCommandParameters()
        val result = controller.signInSubmitCode(parameters)
        assert(result is SignInCommandResult.IncorrectCode)
    }

    @Test
    fun testSignInResendCodeSuccess() {
        val correlationId = UUID.randomUUID().toString()
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInChallenge,
            correlationId = correlationId,
            responseType = MockApiResponseType.CHALLENGE_TYPE_OOB
        )

        val parameters = createSignInResendCodeCommandParameters()
        val result = controller.signInResendCode(parameters)
        assert(result is SignInCommandResult.CodeRequired)
    }

    fun testSignInSubmitPasswordWithPasswordInvalid() {
        val correlationId = UUID.randomUUID().toString()
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInToken,
            correlationId = correlationId,
            responseType = MockApiResponseType.SIGNIN_INVALID_PASSWORD
        )

        val parameters = createSignInSubmitPasswordCommandParameters()
        val result = controller.signInSubmitPassword(parameters)
        assert(result is SignInCommandResult.InvalidCredentials)

        // Verify whether scopes include default scopes
        verify(controller).processSignInInitiateApiResult(
            capture(initiateApiResultCaptor),
            capture(signInStartUsingPasswordCommandParametersWithScopesCaptor),
            capture(oAuth2StrategyCaptor),
            capture(usePasswordCaptor)
        )

        val scopesToCheck = scopes + defaultScopes
        assertTrue(usePasswordCaptor.value)
        assertEquals(scopesToCheck, signInStartUsingPasswordCommandParametersWithScopesCaptor.value?.scopes)
    }

    @Test
    fun testSignInSubmitPasswordWithSuccess() {
        val correlationId = UUID.randomUUID().toString()
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInToken,
            correlationId = correlationId,
            responseType = MockApiResponseType.TOKEN_SUCCESS
        )

        val parameters = createSignInSubmitPasswordCommandParameters()
        val result = controller.signInSubmitPassword(parameters)
        assert(result is SignInCommandResult.Complete)

        // Verify scopes
        verify(controller).performPasswordTokenCall(
            capture(oAuth2StrategyCaptor),
            capture(signInSubmitPasswordCommandParametersWithScopesCaptor)
        )

        val scopesToCheck = scopes + defaultScopes
        assertEquals(scopesToCheck, signInSubmitPasswordCommandParametersWithScopesCaptor.value?.scopes)
    }

    @Test
    fun testSignInStartWithEmailPasswordRequired() {
        val correlationId = UUID.randomUUID().toString()
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInInitiate,
            correlationId = correlationId,
            responseType = MockApiResponseType.INITIATE_SUCCESS
        )
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInChallenge,
            correlationId = correlationId,
            responseType = MockApiResponseType.CHALLENGE_TYPE_PASSWORD
        )

        val parameters = createSignInStartCommandParameters()
        val result = controller.signInStart(parameters)
        assert(result is SignInCommandResult.PasswordRequired)
    }

    @Test
    fun testSignInWithSLTSuccess() {
        val correlationId = UUID.randomUUID().toString()
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInToken,
            correlationId = correlationId,
            responseType = MockApiResponseType.TOKEN_SUCCESS
        )

        val parameters = createSignInWithSLTCommandParameters(withScopes = true)
        val result = controller.signInWithSLT(parameters)
        assert(result is SignInCommandResult.Complete)

        // Verify scopes
        verify(controller).performSLTTokenRequest(
            capture(oAuth2StrategyCaptor),
            capture(signInWithSLTCommandParametersWithScopesCaptor),
        )

        val scopesToCheck = scopes + defaultScopes
        assertEquals(scopesToCheck, signInWithSLTCommandParametersWithScopesCaptor.value?.scopes)
    }

    @Test
    fun testSignInWithSLTInvalidGrant() {
        val correlationId = UUID.randomUUID().toString()
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInToken,
            correlationId = correlationId,
            responseType = MockApiResponseType.INVALID_GRANT
        )

        val parameters = createSignInWithSLTCommandParameters()
        val result = controller.signInWithSLT(parameters)
        assert(result is ICommandResult.UnknownError)
        assert((result as ICommandResult.UnknownError).error == invalidGrantError)
    }

    @Test
    fun testSignInWithSLTCodeIncorrect() {
        val correlationId = UUID.randomUUID().toString()
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInToken,
            correlationId = correlationId,
            responseType = MockApiResponseType.INVALID_OOB_VALUE
        )

        val parameters = createSignInWithSLTCommandParameters()
        val result = controller.signInWithSLT(parameters)
        assert(result is ICommandResult.UnknownError)
        assert((result as ICommandResult.UnknownError).error == invalidGrantError)
    }

    @Test
    fun testSignInWithSLTUserNotFound() {
        val correlationId = UUID.randomUUID().toString()
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInToken,
            correlationId = correlationId,
            responseType = MockApiResponseType.USER_NOT_FOUND
        )

        val parameters = createSignInWithSLTCommandParameters()
        val result = controller.signInWithSLT(parameters)
        assert(result is ICommandResult.UnknownError)
        assert((result as ICommandResult.UnknownError).error == invalidGrantError)
    }

    @Test
    fun testSignInWithSLTPasswordIncorrect() {
        val correlationId = UUID.randomUUID().toString()
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInToken,
            correlationId = correlationId,
            responseType = MockApiResponseType.SIGNIN_INVALID_PASSWORD
        )

        val parameters = createSignInWithSLTCommandParameters()
        val result = controller.signInWithSLT(parameters)
        assert(result is ICommandResult.UnknownError)
        assert((result as ICommandResult.UnknownError).error == invalidGrantError)
    }

    @Test
    fun testSignInStartWithPasswordBrowserRequired() {
        val correlationId = UUID.randomUUID().toString()
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInInitiate,
            correlationId = correlationId,
            responseType = MockApiResponseType.CHALLENGE_TYPE_REDIRECT
        )

        val parameters = createSignInStartWithPasswordCommandParameters()
        val result = controller.signInStart(parameters)
        assert(result is ICommandResult.Redirect)
    }
    //endregion

    // region Sign out
    @Test
    fun testSignOutSuccess() {
        val correlationId = UUID.randomUUID().toString()
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignInToken,
            correlationId = correlationId,
            responseType = MockApiResponseType.TOKEN_SUCCESS
        )

        val signInParameters = createSignInSubmitPasswordCommandParameters()
        val signInResult = controller.signInSubmitPassword(signInParameters) as SignInCommandResult.Complete

        val account = signInResult.authenticationResult.accountRecord as AccountRecord
        val parameters = createRemoveAccountCommandParameters(account)
        val result = localController.removeCurrentAccount(parameters)
        assert(result)
    }

    @Test
    fun testSignOutFailedWithEmptyAccountRecord() {
        val account = AccountRecord()
        val parameters = createRemoveAccountCommandParameters(account)
        val result = localController.removeCurrentAccount(parameters)
        assertFalse(result)
    }
    // endregion

    // region Sspr
    @Test
    fun testSsprStartSsprEmailVerificationRequired() {
        val correlationId = UUID.randomUUID().toString()
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SSPRStart,
            correlationId = correlationId,
            responseType = MockApiResponseType.SSPR_START_SUCCESS
        )

        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SSPRChallenge,
            correlationId = correlationId,
            responseType = MockApiResponseType.CHALLENGE_TYPE_OOB
        )

        val parameters = createSsprStartCommandParameters()
        val result = controller.resetPasswordStart(parameters)
        assert(result is ResetPasswordCommandResult.CodeRequired)
    }

    @Test
    fun testSsprStartSsprRedirect() {
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SSPRStart,
            correlationId = UUID.randomUUID().toString(),
            responseType = MockApiResponseType.CHALLENGE_TYPE_REDIRECT
        )

        val parameters = createSsprStartCommandParameters()
        val result = controller.resetPasswordStart(parameters)
        assert(result is ICommandResult.Redirect)
    }

    @Test
    fun testSsprStartUserNotFound() {
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SSPRStart,
            correlationId = UUID.randomUUID().toString(),
            responseType = MockApiResponseType.EXPLICIT_USER_NOT_FOUND
        )

        val parameters = createSsprStartCommandParameters()
        val result = controller.resetPasswordStart(parameters)
        assert(result is ResetPasswordCommandResult.UserNotFound)
    }

    @Test
    fun testSsprSubmitCodeWithSuccess() {
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SSPRContinue,
            correlationId = UUID.randomUUID().toString(),
            responseType = MockApiResponseType.SSPR_CONTINUE_SUCCESS
        )

        val parameters = createSsprSubmitCodeCommandParameters()
        val result = controller.resetPasswordSubmitCode(parameters)
        assert(result is ResetPasswordCommandResult.PasswordRequired)
    }

    @Test
    fun testSsprSubmitCodeWithInvalidCode() {
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SSPRContinue,
            correlationId = UUID.randomUUID().toString(),
            responseType = MockApiResponseType.EXPLICIT_INVALID_OOB_VALUE
        )

        val parameters = createSsprSubmitCodeCommandParameters()
        val result = controller.resetPasswordSubmitCode(parameters)
        assert(result is ResetPasswordCommandResult.IncorrectCode)
    }

    @Test
    fun testSsprResendCode() {
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SSPRChallenge,
            correlationId = UUID.randomUUID().toString(),
            responseType = MockApiResponseType.CHALLENGE_TYPE_OOB
        )

        val parameters = createSsprResendCodeCommandParameters()
        val result = controller.resetPasswordResendCode(parameters)
        assert(result is ResetPasswordCommandResult.CodeRequired)
    }

    @Test
    fun testSsprSubmitNewPasswordSuccess() {
        val correlationId = UUID.randomUUID().toString()
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SSPRSubmit,
            correlationId = correlationId,
            responseType = MockApiResponseType.SSPR_SUBMIT_SUCCESS
        )

        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SSPRPoll,
            correlationId = correlationId,
            responseType = MockApiResponseType.SSPR_POLL_SUCCESS
        )

        val parameters = createSsprSubmitNewPasswordCommandParameters()
        val result = controller.resetPasswordSubmitNewPassword(parameters)
        assert(result is ResetPasswordCommandResult.Complete)
    }

    @Test
    fun testSsprSubmitNewPasswordFailed() {
        val correlationId = UUID.randomUUID().toString()
        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SSPRSubmit,
            correlationId = correlationId,
            responseType = MockApiResponseType.SSPR_SUBMIT_SUCCESS
        )

        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SSPRPoll,
            correlationId = correlationId,
            responseType = MockApiResponseType.SSPR_POLL_FAILED
        )

        val parameters = createSsprSubmitNewPasswordCommandParameters()
        val result = controller.resetPasswordSubmitNewPassword(parameters)
        assert(result is ResetPasswordCommandResult.PasswordResetFailed)
    }
    // endregion

    // region signup
    @Test
    fun testSignUpStartWithPasswordRequired() {
        val correlationId = UUID.randomUUID().toString()

        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignUpStart,
            correlationId = correlationId,
            responseType = MockApiResponseType.VERIFICATION_REQUIRED
        )

        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignUpChallenge,
            correlationId = correlationId,
            responseType = MockApiResponseType.CHALLENGE_TYPE_PASSWORD
        )

        val parameters = createSignUpStartWithPasswordCommandParameters()
        val result = controller.signUpStart(parameters)
        assert(result is SignUpCommandResult.PasswordRequired)

        // Verify attributes
        verify(controller).performSignUpStartUsingPasswordRequest(
            capture(oAuth2StrategyCaptor),
            capture(signUpStartUsingPasswordCommandParametersCaptor),
        )

        assertEquals(userAttributes, userAttributes)
    }

    @Test
    fun testSignUpStartWithInvalidPassword() {
        val correlationId = UUID.randomUUID().toString()

        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignUpStart,
            correlationId = correlationId,
            responseType = MockApiResponseType.PASSWORD_TOO_LONG
        )

        val parameters = createSignUpStartWithPasswordCommandParameters()
        val result = controller.signUpStart(parameters)
        assert(result is SignUpCommandResult.InvalidPassword)
    }

    @Test
    fun testSignUpStartWithUsernameAlreadyExists() {
        val correlationId = UUID.randomUUID().toString()

        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignUpStart,
            correlationId = correlationId,
            responseType = MockApiResponseType.USER_ALREADY_EXISTS
        )

        val parameters = createSignUpStartCommandParameters()
        val result = controller.signUpStart(parameters)
        assert(result is SignUpCommandResult.UsernameAlreadyExists)

        // Verify attributes
        verify(controller).performSignUpStartRequest(
            capture(oAuth2StrategyCaptor),
            capture(signUpStartCommandParametersCaptor),
        )

        assertEquals(userAttributes, userAttributes)
    }

    @Test
    fun testSignUpStartWithPasswordTooWeak() {
        val correlationId = UUID.randomUUID().toString()

        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignUpStart,
            correlationId = correlationId,
            responseType = MockApiResponseType.PASSWORD_TOO_WEAK
        )

        val parameters = createSignUpStartWithPasswordCommandParameters(passwordValue = "Test@123")
        val result = controller.signUpStart(parameters)
        assert(result is SignUpCommandResult.InvalidPassword)

        // Verify attributes
        verify(controller).performSignUpStartUsingPasswordRequest(
            capture(oAuth2StrategyCaptor),
            capture(signUpStartUsingPasswordCommandParametersCaptor),
        )

        assertEquals(userAttributes, userAttributes)
    }

    @Test
    fun testSignUpStartWithPasswordTooShort() {
        val correlationId = UUID.randomUUID().toString()

        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignUpStart,
            correlationId = correlationId,
            responseType = MockApiResponseType.PASSWORD_TOO_SHORT
        )

        val parameters =
            createSignUpStartWithPasswordCommandParameters(passwordValue = "123")
        val result = controller.signUpStart(parameters)
        assert(result is SignUpCommandResult.InvalidPassword)

        // Verify attributes
        verify(controller).performSignUpStartUsingPasswordRequest(
            capture(oAuth2StrategyCaptor),
            capture(signUpStartUsingPasswordCommandParametersCaptor),
        )

        assertEquals(userAttributes, userAttributes)
    }

    @Test
    fun testSignUpStartWithPasswordBanned() {
        val correlationId = UUID.randomUUID().toString()

        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignUpStart,
            correlationId = correlationId,
            responseType = MockApiResponseType.PASSWORD_BANNED
        )

        val parameters =
            createSignUpStartWithPasswordCommandParameters(passwordValue = "Abc@123")
        val result = controller.signUpStart(parameters)
        assert(result is SignUpCommandResult.InvalidPassword)

        // Verify attributes
        verify(controller).performSignUpStartUsingPasswordRequest(
            capture(oAuth2StrategyCaptor),
            capture(signUpStartUsingPasswordCommandParametersCaptor),
        )

        assertEquals(userAttributes, userAttributes)
    }

    @Test
    fun testSignUpStartWithPasswordTooLong() {
        val correlationId = UUID.randomUUID().toString()

        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignUpStart,
            correlationId = correlationId,
            responseType = MockApiResponseType.PASSWORD_TOO_LONG
        )

        val parameters =
            createSignUpStartWithPasswordCommandParameters(passwordValue = "079af063-4ea7-4dcd-91ff-2b24f54621ea-079af063-4ea7-4dcd-91ff-2b24f54621ea-079af063-4ea7-4dcd-91ff-2b24f54621ea")
        val result = controller.signUpStart(parameters)
        assert(result is SignUpCommandResult.InvalidPassword)

        // Verify attributes
        verify(controller).performSignUpStartUsingPasswordRequest(
            capture(oAuth2StrategyCaptor),
            capture(signUpStartUsingPasswordCommandParametersCaptor),
        )

        assertEquals(userAttributes, userAttributes)
    }

    @Test
    fun testSignUpStartWithPasswordRecentlyUsed() {
        val correlationId = UUID.randomUUID().toString()

        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignUpStart,
            correlationId = correlationId,
            responseType = MockApiResponseType.PASSWORD_RECENTLY_USED
        )

        val parameters =
            createSignUpStartWithPasswordCommandParameters(passwordValue = password)
        val result = controller.signUpStart(parameters)
        assert(result is SignUpCommandResult.InvalidPassword)

        // Verify attributes
        verify(controller).performSignUpStartUsingPasswordRequest(
            capture(oAuth2StrategyCaptor),
            capture(signUpStartUsingPasswordCommandParametersCaptor),
        )

        assertEquals(userAttributes, userAttributes)
    }

    @Test
    fun testSignUpStartWithPasswordAuthenticationNotSupported() {
        val correlationId = UUID.randomUUID().toString()

        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignUpStart,
            correlationId = correlationId,
            responseType = MockApiResponseType.AUTH_NOT_SUPPORTED
        )

        val parameters = createSignUpStartWithPasswordCommandParameters()
        val result = controller.signUpStart(parameters)
        assert(result is SignUpCommandResult.AuthNotSupported)

        // Verify attributes
        verify(controller).performSignUpStartUsingPasswordRequest(
            capture(oAuth2StrategyCaptor),
            capture(signUpStartUsingPasswordCommandParametersCaptor),
        )

        assertEquals(userAttributes, userAttributes)
    }

    @Test
    fun testSignUpStartAuthenticationNotSupported() {
        val correlationId = UUID.randomUUID().toString()

        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignUpStart,
            correlationId = correlationId,
            responseType = MockApiResponseType.AUTH_NOT_SUPPORTED
        )

        val parameters = createSignUpStartCommandParameters()
        val result = controller.signUpStart(parameters)
        assert(result is SignUpCommandResult.AuthNotSupported)
    }

    @Test
    fun testSignUpResendCodeSuccess() {
        val correlationId = UUID.randomUUID().toString()

        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignUpChallenge,
            correlationId = correlationId,
            responseType = MockApiResponseType.CHALLENGE_TYPE_OOB
        )

        val parameters = createSignUpResendCodeCommandParameters()
        val result = controller.signUpResendCode(parameters)
        assert(result is SignUpCommandResult.CodeRequired)
    }

    @Test
    fun testSignUpSubmitCodeSuccess() {
        val correlationId = UUID.randomUUID().toString()

        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignUpContinue,
            correlationId = correlationId,
            responseType = MockApiResponseType.SIGNUP_CONTINUE_SUCCESS
        )

        val parameters = createSignUpSubmitCodeCommandParameters()
        val result = controller.signUpSubmitCode(parameters)
        assert(result is SignUpCommandResult.Complete)
    }

    @Test
    fun testSignUpSubmitPasswordSuccess() {
        val correlationId = UUID.randomUUID().toString()

        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignUpContinue,
            correlationId = correlationId,
            responseType = MockApiResponseType.SIGNUP_CONTINUE_SUCCESS
        )

        val parameters = createSignUpSubmitPasswordCommandParameters()
        val result = controller.signUpSubmitPassword(parameters)
        assert(result is SignUpCommandResult.Complete)
    }

    @Test
    fun testSignUpSubmitPasswordInvalidPassword() {
        val correlationId = UUID.randomUUID().toString()

        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignUpContinue,
            correlationId = correlationId,
            responseType = MockApiResponseType.PASSWORD_TOO_WEAK
        )

        val parameters = createSignUpSubmitPasswordCommandParameters()
        val result = controller.signUpSubmitPassword(parameters)
        assert(result is SignUpCommandResult.InvalidPassword)
    }

    @Test
    fun testSignUpSubmitUserAttributeSuccess() {
        val correlationId = UUID.randomUUID().toString()

        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignUpContinue,
            correlationId = correlationId,
            responseType = MockApiResponseType.SIGNUP_CONTINUE_SUCCESS
        )

        val parameters = createSignUpSubmitUserAttributesCommandParameters()
        val result = controller.signUpSubmitUserAttributes(parameters)
        assert(result is SignUpCommandResult.Complete)

        // Verify attributes
        verify(controller).performSignUpSubmitUserAttributes(
            capture(oAuth2StrategyCaptor),
            capture(signUpSubmitUserAttributesCommandParametersCaptor),
        )

        assertEquals(userAttributes, userAttributes)
    }

    @Test
    fun testSignUpContinueAttributesRequired() {
        val correlationId = UUID.randomUUID().toString()

        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignUpContinue,
            correlationId = correlationId,
            responseType = MockApiResponseType.ATTRIBUTES_REQUIRED
        )

        val parameters = createSignUpSubmitPasswordCommandParameters()
        val result = controller.signUpSubmitPassword(parameters)
        assert(result is SignUpCommandResult.AttributesRequired)
    }

    @Test
    fun testSignUpStartRedirect() {
        val correlationId = UUID.randomUUID().toString()

        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignUpStart,
            correlationId = correlationId,
            responseType = MockApiResponseType.CHALLENGE_TYPE_REDIRECT
        )

        val parameters = createSignUpStartCommandParameters()
        val result = controller.signUpStart(parameters)
        assert(result is ICommandResult.Redirect)
    }

    @Test
    fun testSignUpStartWithPasswordRedirect() {
        val correlationId = UUID.randomUUID().toString()

        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignUpStart,
            correlationId = correlationId,
            responseType = MockApiResponseType.CHALLENGE_TYPE_REDIRECT
        )

        val parameters = createSignUpStartWithPasswordCommandParameters()
        val result = controller.signUpStart(parameters)
        assert(result is ICommandResult.Redirect)
    }

    @Test
    fun testSignUpChallengeRedirect() {
        val correlationId = UUID.randomUUID().toString()

        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignUpStart,
            correlationId = correlationId,
            responseType = MockApiResponseType.VERIFICATION_REQUIRED
        )

        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignUpChallenge,
            correlationId = correlationId,
            responseType = MockApiResponseType.CHALLENGE_TYPE_REDIRECT
        )

        val parameters = createSignUpStartWithPasswordCommandParameters()
        val result = controller.signUpStart(parameters)
        assert(result is ICommandResult.Redirect)
    }

    @Test
    fun testSignUpAdditionalAttributesRequired() {
        val correlationId = UUID.randomUUID().toString()

        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignUpContinue,
            correlationId = correlationId,
            responseType = MockApiResponseType.ATTRIBUTES_REQUIRED
        )

        val parameters = createSignUpSubmitUserAttributesCommandParameters()
        val result = controller.signUpSubmitUserAttributes(parameters)
        assert(result is SignUpCommandResult.AttributesRequired)
    }

    @Test
    fun testSignUpInvalidOOB() {
        val correlationId = UUID.randomUUID().toString()

        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignUpContinue,
            correlationId = correlationId,
            responseType = MockApiResponseType.EXPLICIT_INVALID_OOB_VALUE
        )

        val parameters = createSignUpSubmitCodeCommandParameters()
        val result = controller.signUpSubmitCode(parameters)
        assert(result is SignUpCommandResult.InvalidCode)
    }

    @Test
    fun testSignUpSubmitUserAttributesWithInvalidUserAttributes() {
        val correlationId = UUID.randomUUID().toString()

        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignUpContinue,
            correlationId = correlationId,
            responseType = MockApiResponseType.ATTRIBUTE_VALIDATION_FAILED
        )

        val parameters = createSignUpSubmitUserAttributesCommandParameters()
        val result = controller.signUpSubmitUserAttributes(parameters)
        assert(result is SignUpCommandResult.InvalidAttributes)
    }

    @Test
    fun testSignUpStartWithInvalidUserAttributes() {
        val correlationId = UUID.randomUUID().toString()

        MockApiUtils.configureMockApi(
            endpointType = MockApiEndpointType.SignUpStart,
            correlationId = correlationId,
            responseType = MockApiResponseType.ATTRIBUTE_VALIDATION_FAILED
        )

        val parameters = createSignUpStartCommandParameters()
        val result = controller.signUpStart(parameters)
        assert(result is SignUpCommandResult.InvalidAttributes)
    }
    // endregion

    private fun createSignInStartWithPasswordCommandParameters(): SignInStartUsingPasswordCommandParameters {
        val authenticationScheme = AuthenticationSchemeFactory.createScheme(
            AndroidPlatformComponentsFactory.createFromContext(context),
            null
        )

        return SignInStartUsingPasswordCommandParameters.builder()
            .username(username)
            .password(password)
            .scopes(scopes)
            .authenticationScheme(authenticationScheme)
            .authority(NativeAuthCIAMAuthority.getAuthorityFromAuthorityUrl(authorityUrl, clientId))
            .clientId(clientId)
            .platformComponents(platformComponents)
            .oAuth2TokenCache(createCache())
            .sdkType(SdkType.MSAL)
            .requiredBrokerProtocolVersion(BrokerProtocolVersionUtil.MSAL_TO_BROKER_PROTOCOL_COMPRESSION_CHANGES_MINIMUM_VERSION)
            .build()
    }

    private fun createSignInStartCommandParameters(): SignInStartCommandParameters {
        val authenticationScheme = AuthenticationSchemeFactory.createScheme(
            AndroidPlatformComponentsFactory.createFromContext(context),
            null
        )

        return SignInStartCommandParameters.builder()
            .username(username)
            .authenticationScheme(authenticationScheme)
            .authority(NativeAuthCIAMAuthority.getAuthorityFromAuthorityUrl(authorityUrl, clientId))
            .clientId(clientId)
            .platformComponents(platformComponents)
            .oAuth2TokenCache(createCache())
            .sdkType(SdkType.MSAL)
            .requiredBrokerProtocolVersion(BrokerProtocolVersionUtil.MSAL_TO_BROKER_PROTOCOL_COMPRESSION_CHANGES_MINIMUM_VERSION)
            .build()
    }

    private fun createSignInWithSLTCommandParameters(withScopes: Boolean = false): SignInWithSLTCommandParameters {
        val authenticationScheme = AuthenticationSchemeFactory.createScheme(
            AndroidPlatformComponentsFactory.createFromContext(context),
            null
        )

        return SignInWithSLTCommandParameters.builder()
            .authenticationScheme(authenticationScheme)
            .authority(NativeAuthCIAMAuthority.getAuthorityFromAuthorityUrl(authorityUrl, clientId))
            .clientId(clientId)
            .scopes(if (withScopes) scopes else emptyList())
            .platformComponents(platformComponents)
            .oAuth2TokenCache(createCache())
            .sdkType(SdkType.MSAL)
            .requiredBrokerProtocolVersion(BrokerProtocolVersionUtil.MSAL_TO_BROKER_PROTOCOL_COMPRESSION_CHANGES_MINIMUM_VERSION)
            .signInSLT(signInSLT)
            .build()
    }

    private fun createSignInSubmitCodeCommandParameters(): SignInSubmitCodeCommandParameters {
        val authenticationScheme = AuthenticationSchemeFactory.createScheme(
            AndroidPlatformComponentsFactory.createFromContext(context),
            null
        )

        return SignInSubmitCodeCommandParameters.builder()
            .code(code)
            .authenticationScheme(authenticationScheme)
            .credentialToken(credentialToken)
            .authority(NativeAuthCIAMAuthority.getAuthorityFromAuthorityUrl(authorityUrl, clientId))
            .clientId(clientId)
            .platformComponents(platformComponents)
            .oAuth2TokenCache(createCache())
            .sdkType(SdkType.MSAL)
            .requiredBrokerProtocolVersion(BrokerProtocolVersionUtil.MSAL_TO_BROKER_PROTOCOL_COMPRESSION_CHANGES_MINIMUM_VERSION)
            .build()
    }

    private fun createSignInResendCodeCommandParameters(): SignInResendCodeCommandParameters {
        return SignInResendCodeCommandParameters.builder()
            .authority(NativeAuthCIAMAuthority.getAuthorityFromAuthorityUrl(authorityUrl, clientId))
            .clientId(clientId)
            .credentialToken(credentialToken)
            .platformComponents(platformComponents)
            .oAuth2TokenCache(createCache())
            .sdkType(SdkType.MSAL)
            .requiredBrokerProtocolVersion(BrokerProtocolVersionUtil.MSAL_TO_BROKER_PROTOCOL_COMPRESSION_CHANGES_MINIMUM_VERSION)
            .build()
    }

    private fun createSignInSubmitPasswordCommandParameters(): SignInSubmitPasswordCommandParameters {
        val authenticationScheme = AuthenticationSchemeFactory.createScheme(
            AndroidPlatformComponentsFactory.createFromContext(context),
            null
        )

        return SignInSubmitPasswordCommandParameters.builder()
            .password(password)
            .scopes(scopes)
            .authenticationScheme(authenticationScheme)
            .authority(NativeAuthCIAMAuthority.getAuthorityFromAuthorityUrl(authorityUrl, clientId))
            .clientId(clientId)
            .credentialToken(credentialToken)
            .platformComponents(platformComponents)
            .oAuth2TokenCache(createCache())
            .sdkType(SdkType.MSAL)
            .requiredBrokerProtocolVersion(BrokerProtocolVersionUtil.MSAL_TO_BROKER_PROTOCOL_COMPRESSION_CHANGES_MINIMUM_VERSION)
            .build()
    }

    private fun createSsprStartCommandParameters(): ResetPasswordStartCommandParameters {
        return ResetPasswordStartCommandParameters.builder()
            .username(username)
            .authority(NativeAuthCIAMAuthority.getAuthorityFromAuthorityUrl(authorityUrl, clientId))
            .clientId(clientId)
            .platformComponents(platformComponents)
            .oAuth2TokenCache(createCache())
            .sdkType(SdkType.MSAL)
            .requiredBrokerProtocolVersion(BrokerProtocolVersionUtil.MSAL_TO_BROKER_PROTOCOL_COMPRESSION_CHANGES_MINIMUM_VERSION)
            .build()
    }

    private fun createSsprSubmitCodeCommandParameters(): ResetPasswordSubmitCodeCommandParameters {
        return ResetPasswordSubmitCodeCommandParameters.builder()
            .code(code)
            .passwordResetToken(passwordResetToken)
            .authority(NativeAuthCIAMAuthority.getAuthorityFromAuthorityUrl(authorityUrl, clientId))
            .clientId(clientId)
            .platformComponents(platformComponents)
            .oAuth2TokenCache(createCache())
            .sdkType(SdkType.MSAL)
            .requiredBrokerProtocolVersion(BrokerProtocolVersionUtil.MSAL_TO_BROKER_PROTOCOL_COMPRESSION_CHANGES_MINIMUM_VERSION)
            .build()
    }

    private fun createSsprResendCodeCommandParameters(): ResetPasswordResendCodeCommandParameters {
        return ResetPasswordResendCodeCommandParameters.builder()
            .authority(NativeAuthCIAMAuthority.getAuthorityFromAuthorityUrl(authorityUrl, clientId))
            .clientId(clientId)
            .passwordResetToken(passwordResetToken)
            .platformComponents(platformComponents)
            .oAuth2TokenCache(createCache())
            .sdkType(SdkType.MSAL)
            .requiredBrokerProtocolVersion(BrokerProtocolVersionUtil.MSAL_TO_BROKER_PROTOCOL_COMPRESSION_CHANGES_MINIMUM_VERSION)
            .build()
    }

    private fun createSsprSubmitNewPasswordCommandParameters(): ResetPasswordSubmitNewPasswordCommandParameters {
        return ResetPasswordSubmitNewPasswordCommandParameters.builder()
            .newPassword(newPassword)
            .passwordSubmitToken(passwordSubmitToken)
            .authority(NativeAuthCIAMAuthority.getAuthorityFromAuthorityUrl(authorityUrl, clientId))
            .clientId(clientId)
            .platformComponents(platformComponents)
            .oAuth2TokenCache(createCache())
            .sdkType(SdkType.MSAL)
            .requiredBrokerProtocolVersion(BrokerProtocolVersionUtil.MSAL_TO_BROKER_PROTOCOL_COMPRESSION_CHANGES_MINIMUM_VERSION)
            .build()
    }

    private fun createRemoveAccountCommandParameters(account: AccountRecord): RemoveAccountCommandParameters {
        return RemoveAccountCommandParameters.builder()
            .account(account)
            .clientId(clientId)
            .platformComponents(platformComponents)
            .oAuth2TokenCache(createCache())
            .sdkType(SdkType.MSAL)
            .build()
    }

    private fun createCache(): MsalOAuth2TokenCache<*, *, *, *, *> {
        return MsalOAuth2TokenCache.create(platformComponents)
    }

    private fun createSignUpStartWithPasswordCommandParameters(passwordValue: String? = null): SignUpStartUsingPasswordCommandParameters {
        return SignUpStartUsingPasswordCommandParameters.builder()
            .username(username)
            .password(
                if (passwordValue.isNullOrBlank()) {
                    password
                } else {
                    passwordValue
                }
            )
            .authority(NativeAuthCIAMAuthority.getAuthorityFromAuthorityUrl(authorityUrl, clientId))
            .clientId(clientId)
            .userAttributes(userAttributes)
            .platformComponents(platformComponents)
            .oAuth2TokenCache(createCache())
            .sdkType(SdkType.MSAL)
            .requiredBrokerProtocolVersion(BrokerProtocolVersionUtil.MSAL_TO_BROKER_PROTOCOL_COMPRESSION_CHANGES_MINIMUM_VERSION)
            .build()
    }

    private fun createSignUpStartCommandParameters(): SignUpStartCommandParameters {
        return SignUpStartCommandParameters.builder()
            .username(username)
            .authority(NativeAuthCIAMAuthority.getAuthorityFromAuthorityUrl(authorityUrl, clientId))
            .clientId(clientId)
            .platformComponents(platformComponents)
            .oAuth2TokenCache(createCache())
            .sdkType(SdkType.MSAL)
            .requiredBrokerProtocolVersion(BrokerProtocolVersionUtil.MSAL_TO_BROKER_PROTOCOL_COMPRESSION_CHANGES_MINIMUM_VERSION)
            .build()
    }

    private fun createSignUpResendCodeCommandParameters(): SignUpResendCodeCommandParameters {
        return SignUpResendCodeCommandParameters.builder()
            .authority(NativeAuthCIAMAuthority.getAuthorityFromAuthorityUrl(authorityUrl, clientId))
            .signupToken(signUpToken)
            .clientId(clientId)
            .platformComponents(platformComponents)
            .oAuth2TokenCache(createCache())
            .sdkType(SdkType.MSAL)
            .requiredBrokerProtocolVersion(BrokerProtocolVersionUtil.MSAL_TO_BROKER_PROTOCOL_COMPRESSION_CHANGES_MINIMUM_VERSION)
            .build()
    }

    private fun createSignUpSubmitCodeCommandParameters(): SignUpSubmitCodeCommandParameters {
        return SignUpSubmitCodeCommandParameters.builder()
            .signupToken(signUpToken)
            .code(code)
            .authority(NativeAuthCIAMAuthority.getAuthorityFromAuthorityUrl(authorityUrl, clientId))
            .clientId(clientId)
            .platformComponents(platformComponents)
            .oAuth2TokenCache(createCache())
            .sdkType(SdkType.MSAL)
            .requiredBrokerProtocolVersion(BrokerProtocolVersionUtil.MSAL_TO_BROKER_PROTOCOL_COMPRESSION_CHANGES_MINIMUM_VERSION)
            .build()
    }

    private fun createSignUpSubmitPasswordCommandParameters(): SignUpSubmitPasswordCommandParameters {
        return SignUpSubmitPasswordCommandParameters.builder()
            .signupToken(signUpToken)
            .password(password)
            .authority(NativeAuthCIAMAuthority.getAuthorityFromAuthorityUrl(authorityUrl, clientId))
            .clientId(clientId)
            .platformComponents(platformComponents)
            .oAuth2TokenCache(createCache())
            .sdkType(SdkType.MSAL)
            .requiredBrokerProtocolVersion(BrokerProtocolVersionUtil.MSAL_TO_BROKER_PROTOCOL_COMPRESSION_CHANGES_MINIMUM_VERSION)
            .build()
    }

    private fun createSignUpSubmitUserAttributesCommandParameters(): SignUpSubmitUserAttributesCommandParameters {
        return SignUpSubmitUserAttributesCommandParameters.builder()
            .signupToken(signUpToken)
            .userAttributes(userAttributes)
            .authority(NativeAuthCIAMAuthority.getAuthorityFromAuthorityUrl(authorityUrl, clientId))
            .clientId(clientId)
            .platformComponents(platformComponents)
            .oAuth2TokenCache(createCache())
            .sdkType(SdkType.MSAL)
            .requiredBrokerProtocolVersion(BrokerProtocolVersionUtil.MSAL_TO_BROKER_PROTOCOL_COMPRESSION_CHANGES_MINIMUM_VERSION)
            .build()
    }
}
