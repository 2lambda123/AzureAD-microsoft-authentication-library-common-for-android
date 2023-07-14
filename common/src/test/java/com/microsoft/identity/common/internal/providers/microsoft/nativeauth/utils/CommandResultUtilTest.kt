package com.microsoft.identity.common.internal.util

import com.microsoft.identity.common.java.commands.ICommandResult.ResultStatus
import com.microsoft.identity.common.java.controllers.CommandResult
import com.microsoft.identity.common.java.controllers.results.ICommandResult
import com.microsoft.identity.common.java.controllers.results.ResetPasswordCommandResult
import com.microsoft.identity.common.java.controllers.results.ResetPasswordResendCodeCommandResult
import com.microsoft.identity.common.java.controllers.results.ResetPasswordStartCommandResult
import com.microsoft.identity.common.java.controllers.results.ResetPasswordSubmitCodeCommandResult
import com.microsoft.identity.common.java.controllers.results.ResetPasswordSubmitNewPasswordCommandResult
import com.microsoft.identity.common.java.controllers.results.SignInCommandResult
import com.microsoft.identity.common.java.controllers.results.SignInResendCodeCommandResult
import com.microsoft.identity.common.java.controllers.results.SignInStartCommandResult
import com.microsoft.identity.common.java.controllers.results.SignInSubmitCodeCommandResult
import com.microsoft.identity.common.java.controllers.results.SignInSubmitPasswordCommandResult
import com.microsoft.identity.common.java.controllers.results.SignInWithSLTCommandResult
import com.microsoft.identity.common.java.controllers.results.SignUpCommandResult
import com.microsoft.identity.common.java.controllers.results.SignUpResendCodeCommandResult
import com.microsoft.identity.common.java.controllers.results.SignUpStartCommandResult
import com.microsoft.identity.common.java.controllers.results.SignUpSubmitCodeCommandResult
import com.microsoft.identity.common.java.controllers.results.SignUpSubmitPasswordCommandResult
import com.microsoft.identity.common.java.controllers.results.SignUpSubmitUserAttributesCommandResult
import com.microsoft.identity.common.java.exception.ClientException
import com.microsoft.identity.common.java.result.ILocalAuthenticationResult
import com.microsoft.identity.common.java.util.checkAndWrapCommandResultType
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized
import org.junit.runners.Parameterized.Parameters

private const val SIGNUP_TOKEN = "1234"
private const val CREDENTIAL_TOKEN = "ABCD"
private const val PASSWORD_RESET_TOKEN = "klsdjf"
private const val PASSWORD_SUBMIT_TOKEN = "ioamf43"
private const val ERROR = "error_code"
private const val ERROR_DESCRIPTION = "error description"
private const val CHALLENGE_TARGET_LABEL = "user@contoso.com"
private const val CHALLENGE_TYPE = "email"
private const val CODE_LENGTH = 6

/**
 * Split into multiple tests, as JUnit4 doesn't have support for @MethodSource like JUnit5 does.
 */

//region sign-up
private val signUpAttributesRequiredCommandResult = SignUpCommandResult.AttributesRequired(
    signupToken = SIGNUP_TOKEN,
    error = ERROR,
    errorDescription = ERROR_DESCRIPTION,
    requiredAttributes = emptyList()
)

private val signUpAuthNotSupportedCommandResult = SignUpCommandResult.AuthNotSupported(
    error = ERROR,
    errorDescription = ERROR_DESCRIPTION,
)

private val signUpCodeRequiredCommandResult = SignUpCommandResult.CodeRequired(
    signupToken = SIGNUP_TOKEN,
    challengeChannel = CHALLENGE_TYPE,
    challengeTargetLabel = CHALLENGE_TARGET_LABEL,
    codeLength = CODE_LENGTH
)

private val signUpCompleteCommandResult = SignUpCommandResult.Complete(
    signInSLT = null,
    expiresIn = null
)

private val signUpInvalidAttributesCommandResult = SignUpCommandResult.InvalidAttributes(
    error = ERROR,
    errorDescription = ERROR_DESCRIPTION,
    invalidAttributes = emptyList()
)

private val signUpInvalidCodeCommandResult = SignUpCommandResult.InvalidCode(
    error = ERROR,
    errorDescription = ERROR_DESCRIPTION,
)

private val signUpInvalidPasswordCommandResult = SignUpCommandResult.InvalidPassword(
    error = ERROR,
    errorDescription = ERROR_DESCRIPTION,
)

private val signUpPasswordRequiredCommandResult = SignUpCommandResult.PasswordRequired(
    signupToken = SIGNUP_TOKEN,
)

private val signUpUsernameAlreadyExistsCommandResult = SignUpCommandResult.UsernameAlreadyExists(
    error = ERROR,
    errorDescription = ERROR_DESCRIPTION,
)

private val redirectCommandResult = ICommandResult.Redirect()

private val unknownErrorCommandResult = ICommandResult.UnknownError(
    error = ERROR,
    errorDescription = ERROR_DESCRIPTION,
)

// SignUpStartCommandResult
@RunWith(Parameterized::class)
class CommandResultUtilTestSignUpStartCommandResult(private val resultValue: Any) {

    companion object {
        @JvmStatic
        @Parameters
        fun getSignUpStartCommandResults() = listOf(
            signUpAttributesRequiredCommandResult,
            signUpAuthNotSupportedCommandResult,
            signUpCodeRequiredCommandResult,
            signUpCompleteCommandResult,
            signUpInvalidAttributesCommandResult,
            signUpInvalidPasswordCommandResult,
            signUpPasswordRequiredCommandResult,
            redirectCommandResult,
            unknownErrorCommandResult,
            signUpUsernameAlreadyExistsCommandResult
        )
    }

    @Test
    fun checkAndWrapCommandResultTypeSignUpStartCommandResultSuccess() {
        val commandResult = CommandResult<Any>(
            ResultStatus.COMPLETED,
            resultValue,
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<SignUpStartCommandResult>()
        assertEquals(resultValue.javaClass, result.javaClass)
    }

    @Test
    fun testCheckAndWrapCommandResultTypeCompletedStatusWrongType() {
        val commandResult = CommandResult<Any>(
            ResultStatus.COMPLETED,
            ResetPasswordCommandResult.Complete,
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<SignUpStartCommandResult>()
        assertTrue(result is ICommandResult.UnknownError)
    }

    @Test
    fun testCheckAndWrapCommandResultTypeErrorStatus() {
        val commandResult = CommandResult<Any>(
            ResultStatus.ERROR,
            ClientException(
                ERROR
            ),
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<SignUpStartCommandResult>()
        assertTrue(result is ICommandResult.UnknownError)
    }

    @Test
    fun testCheckAndWrapCommandResultTypeCompletedStatusWithException() {
        val commandResult = CommandResult<Any>(
            ResultStatus.COMPLETED,
            ClientException(
                ERROR
            ),
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<SignUpStartCommandResult>()
        assertTrue(result is ICommandResult.UnknownError)
    }
}

// SignUpSubmitCodeCommandResult
@RunWith(Parameterized::class)
class CommandResultUtilTestSignUpSubmitCodeCommandResult(private val resultValue: Any) {

    companion object {
        @JvmStatic
        @Parameters(name = "{0}")
        fun getSignUpSubmitCodeCommandResults() = listOf(
            signUpAttributesRequiredCommandResult,
            signUpCompleteCommandResult,
            signUpInvalidCodeCommandResult,
            redirectCommandResult,
            unknownErrorCommandResult,
            signUpUsernameAlreadyExistsCommandResult
        )
    }

    @Test
    fun checkAndWrapCommandResultTypeSignUpSubmitCodeCommandResultSuccess() {
        val commandResult = CommandResult<Any>(
            ResultStatus.COMPLETED,
            resultValue,
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<SignUpSubmitCodeCommandResult>()
        assertEquals(resultValue.javaClass, result.javaClass)
    }

    @Test
    fun testCheckAndWrapCommandResultTypeCompletedStatusWrongType() {
        val commandResult = CommandResult<Any>(
            ResultStatus.COMPLETED,
            ResetPasswordCommandResult.Complete,
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<SignUpSubmitCodeCommandResult>()
        assertTrue(result is ICommandResult.UnknownError)
    }

    @Test
    fun testCheckAndWrapCommandResultTypeErrorStatus() {
        val commandResult = CommandResult<Any>(
            ResultStatus.ERROR,
            ClientException(
                ERROR
            ),
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<SignUpSubmitCodeCommandResult>()
        assertTrue(result is ICommandResult.UnknownError)
    }

    @Test
    fun testCheckAndWrapCommandResultTypeCompletedStatusWithException() {
        val commandResult = CommandResult<Any>(
            ResultStatus.COMPLETED,
            ClientException(
                ERROR
            ),
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<SignUpSubmitCodeCommandResult>()
        assertTrue(result is ICommandResult.UnknownError)
    }
}

// SignUpSubmitUserAttributesCommandResult
@RunWith(Parameterized::class)
class CommandResultUtilTestSignUpSignUpSubmitUserAttributesCommandResult(private val resultValue: Any) {

    companion object {
        @JvmStatic
        @Parameters(name = "{0}")
        fun getSignUpSubmitUserAttributesCommandResults() = listOf(
            signUpAttributesRequiredCommandResult,
            signUpCompleteCommandResult,
            signUpInvalidAttributesCommandResult,
            redirectCommandResult,
            unknownErrorCommandResult,
            signUpUsernameAlreadyExistsCommandResult
        )
    }

    @Test
    fun checkAndWrapCommandResultTypeSignUpSubmitUserAttributesCommandResultSuccess() {
        val commandResult = CommandResult<Any>(
            ResultStatus.COMPLETED,
            resultValue,
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<SignUpSubmitUserAttributesCommandResult>()
        assertEquals(resultValue.javaClass, result.javaClass)
    }

    @Test
    fun testCheckAndWrapCommandResultTypeCompletedStatusWrongType() {
        val commandResult = CommandResult<Any>(
            ResultStatus.COMPLETED,
            ResetPasswordCommandResult.Complete,
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<SignUpSubmitUserAttributesCommandResult>()
        assertTrue(result is ICommandResult.UnknownError)
    }

    @Test
    fun testCheckAndWrapCommandResultTypeErrorStatus() {
        val commandResult = CommandResult<Any>(
            ResultStatus.ERROR,
            ClientException(
                ERROR
            ),
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<SignUpSubmitUserAttributesCommandResult>()
        assertTrue(result is ICommandResult.UnknownError)
    }

    @Test
    fun testCheckAndWrapCommandResultTypeCompletedStatusWithException() {
        val commandResult = CommandResult<Any>(
            ResultStatus.COMPLETED,
            ClientException(
                ERROR
            ),
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<SignUpSubmitUserAttributesCommandResult>()
        assertTrue(result is ICommandResult.UnknownError)
    }
}

// SignUpSubmitPasswordCommandResult
@RunWith(Parameterized::class)
class CommandResultUtilTestSignUpSubmitPasswordCommandResult(private val resultValue: Any) {

    companion object {
        @JvmStatic
        @Parameters(name = "{0}")
        fun getSignUpSubmitPasswordCommandResults() = listOf(
            signUpAttributesRequiredCommandResult,
            signUpCompleteCommandResult,
            signUpInvalidPasswordCommandResult,
            redirectCommandResult,
            unknownErrorCommandResult,
            signUpUsernameAlreadyExistsCommandResult
        )
    }

    @Test
    fun checkAndWrapCommandResultTypeSignUpSubmitPasswordCommandResultSuccess() {
        val commandResult = CommandResult<Any>(
            ResultStatus.COMPLETED,
            resultValue,
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<SignUpSubmitPasswordCommandResult>()
        assertEquals(resultValue.javaClass, result.javaClass)
    }

    @Test
    fun testCheckAndWrapCommandResultTypeCompletedStatusWrongType() {
        val commandResult = CommandResult<Any>(
            ResultStatus.COMPLETED,
            ResetPasswordCommandResult.Complete,
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<SignUpSubmitPasswordCommandResult>()
        assertTrue(result is ICommandResult.UnknownError)
    }

    @Test
    fun testCheckAndWrapCommandResultTypeErrorStatus() {
        val commandResult = CommandResult<Any>(
            ResultStatus.ERROR,
            ClientException(
                ERROR
            ),
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<SignUpSubmitPasswordCommandResult>()
        assertTrue(result is ICommandResult.UnknownError)
    }

    @Test
    fun testCheckAndWrapCommandResultTypeCompletedStatusWithException() {
        val commandResult = CommandResult<Any>(
            ResultStatus.COMPLETED,
            ClientException(
                ERROR
            ),
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<SignUpSubmitPasswordCommandResult>()
        assertTrue(result is ICommandResult.UnknownError)
    }
}

// SignUpResendCodeCommandResult
@RunWith(Parameterized::class)
class CommandResultUtilTestSignUpResendCodeCommandResult(private val resultValue: Any) {

    companion object {
        @JvmStatic
        @Parameters(name = "{0}")
        fun getSignUpResendCodeCommandResults() = listOf(
            signUpCodeRequiredCommandResult,
            redirectCommandResult,
            unknownErrorCommandResult,
        )
    }

    @Test
    fun checkAndWrapCommandResultTypeSignUpResendCodeCommandResultSuccess() {
        val commandResult = CommandResult<Any>(
            ResultStatus.COMPLETED,
            resultValue,
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<SignUpResendCodeCommandResult>()
        assertEquals(resultValue.javaClass, result.javaClass)
    }

    @Test
    fun testCheckAndWrapCommandResultTypeCompletedStatusWrongType() {
        val commandResult = CommandResult<Any>(
            ResultStatus.COMPLETED,
            ResetPasswordCommandResult.Complete,
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<SignUpResendCodeCommandResult>()
        assertTrue(result is ICommandResult.UnknownError)
    }

    @Test
    fun testCheckAndWrapCommandResultTypeErrorStatus() {
        val commandResult = CommandResult<Any>(
            ResultStatus.ERROR,
            ClientException(
                ERROR
            ),
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<SignUpResendCodeCommandResult>()
        assertTrue(result is ICommandResult.UnknownError)
    }

    @Test
    fun testCheckAndWrapCommandResultTypeCompletedStatusWithException() {
        val commandResult = CommandResult<Any>(
            ResultStatus.COMPLETED,
            ClientException(
                ERROR
            ),
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<SignUpResendCodeCommandResult>()
        assertTrue(result is ICommandResult.UnknownError)
    }
}
//endregion

//region sign-in
private val signInCodeRequiredCommandResult = SignInCommandResult.CodeRequired(
    credentialToken = CREDENTIAL_TOKEN,
    challengeChannel = CHALLENGE_TYPE,
    challengeTargetLabel = CHALLENGE_TARGET_LABEL,
    codeLength = CODE_LENGTH
)

private val signInCompleteCommandResult = SignInCommandResult.Complete(
    authenticationResult = mockk<ILocalAuthenticationResult>()
)

private val signInInvalidCredentialsCommandResult = SignInCommandResult.InvalidCredentials(
    error = ERROR,
    errorDescription = ERROR_DESCRIPTION,
    errorCodes = emptyList()
)

private val signInIncorrectCodeCommandResult = SignInCommandResult.IncorrectCode(
    error = ERROR,
    errorDescription = ERROR_DESCRIPTION,
    errorCodes = emptyList()
)

private val signInPasswordRequiredCommandResult = SignInCommandResult.PasswordRequired(
    credentialToken = CREDENTIAL_TOKEN
)

private val signInUserNotFoundCommandResult = SignInCommandResult.UserNotFound(
    error = ERROR,
    errorDescription = ERROR_DESCRIPTION,
    errorCodes = emptyList()
)

// SignInStartCommandResult
@RunWith(Parameterized::class)
class CommandResultUtilTestSignInStartCommandResult(private val resultValue: Any) {

    companion object {
        @JvmStatic
        @Parameters
        fun getSignInStartCommandResults() = listOf(
            signInCodeRequiredCommandResult,
            signInCompleteCommandResult,
            signInInvalidCredentialsCommandResult,
            signInPasswordRequiredCommandResult,
            signInUserNotFoundCommandResult,
            redirectCommandResult,
            unknownErrorCommandResult
        )
    }

    @Test
    fun checkAndWrapCommandResultTypeSignInStartCommandResultSuccess() {
        val commandResult = CommandResult<Any>(
            ResultStatus.COMPLETED,
            resultValue,
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<SignInStartCommandResult>()
        assertEquals(resultValue.javaClass, result.javaClass)
    }

    @Test
    fun testCheckAndWrapCommandResultTypeCompletedStatusWrongType() {
        val commandResult = CommandResult<Any>(
            ResultStatus.COMPLETED,
            ResetPasswordCommandResult.Complete,
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<SignInStartCommandResult>()
        assertTrue(result is ICommandResult.UnknownError)
    }

    @Test
    fun testCheckAndWrapCommandResultTypeErrorStatus() {
        val commandResult = CommandResult<Any>(
            ResultStatus.ERROR,
            ClientException(
                ERROR
            ),
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<SignInStartCommandResult>()
        assertTrue(result is ICommandResult.UnknownError)
    }

    @Test
    fun testCheckAndWrapCommandResultTypeCompletedStatusWithException() {
        val commandResult = CommandResult<Any>(
            ResultStatus.COMPLETED,
            ClientException(
                ERROR
            ),
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<SignInStartCommandResult>()
        assertTrue(result is ICommandResult.UnknownError)
    }
}

// SignUpStartCommandResult
@RunWith(Parameterized::class)
class CommandResultUtilTestSignInWithSLTCommandResult(private val resultValue: Any) {

    companion object {
        @JvmStatic
        @Parameters
        fun getSignInWithSLTCommandResults() = listOf(
            signInCodeRequiredCommandResult,
            signInCompleteCommandResult,
            signInPasswordRequiredCommandResult,
            redirectCommandResult,
            unknownErrorCommandResult
        )
    }

    @Test
    fun checkAndWrapCommandResultTypeSignInWithSLTCommandResultSuccess() {
        val commandResult = CommandResult<Any>(
            ResultStatus.COMPLETED,
            resultValue,
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<SignInWithSLTCommandResult>()
        assertEquals(resultValue.javaClass, result.javaClass)
    }

    @Test
    fun testCheckAndWrapCommandResultTypeCompletedStatusWrongType() {
        val commandResult = CommandResult<Any>(
            ResultStatus.COMPLETED,
            ResetPasswordCommandResult.Complete,
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<SignInWithSLTCommandResult>()
        assertTrue(result is ICommandResult.UnknownError)
    }

    @Test
    fun testCheckAndWrapCommandResultTypeErrorStatus() {
        val commandResult = CommandResult<Any>(
            ResultStatus.ERROR,
            ClientException(
                ERROR
            ),
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<SignInWithSLTCommandResult>()
        assertTrue(result is ICommandResult.UnknownError)
    }

    @Test
    fun testCheckAndWrapCommandResultTypeCompletedStatusWithException() {
        val commandResult = CommandResult<Any>(
            ResultStatus.COMPLETED,
            ClientException(
                ERROR
            ),
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<SignInWithSLTCommandResult>()
        assertTrue(result is ICommandResult.UnknownError)
    }
}

// SignInSubmitCodeCommandResult
@RunWith(Parameterized::class)
class CommandResultUtilTestSignInSubmitCodeCommandResult(private val resultValue: Any) {

    companion object {
        @JvmStatic
        @Parameters
        fun getSignInSubmitCodeCommandResults() = listOf(
            signInCompleteCommandResult,
            signInIncorrectCodeCommandResult,
            redirectCommandResult,
            unknownErrorCommandResult
        )
    }

    @Test
    fun checkAndWrapCommandResultTypeSignInSubmitCodeCommandResultSuccess() {
        val commandResult = CommandResult<Any>(
            ResultStatus.COMPLETED,
            resultValue,
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<SignInSubmitCodeCommandResult>()
        assertEquals(resultValue.javaClass, result.javaClass)
    }

    @Test
    fun testCheckAndWrapCommandResultTypeCompletedStatusWrongType() {
        val commandResult = CommandResult<Any>(
            ResultStatus.COMPLETED,
            ResetPasswordCommandResult.Complete,
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<SignInSubmitCodeCommandResult>()
        assertTrue(result is ICommandResult.UnknownError)
    }

    @Test
    fun testCheckAndWrapCommandResultTypeErrorStatus() {
        val commandResult = CommandResult<Any>(
            ResultStatus.ERROR,
            ClientException(
                ERROR
            ),
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<SignInSubmitCodeCommandResult>()
        assertTrue(result is ICommandResult.UnknownError)
    }

    @Test
    fun testCheckAndWrapCommandResultTypeCompletedStatusWithException() {
        val commandResult = CommandResult<Any>(
            ResultStatus.COMPLETED,
            ClientException(
                ERROR
            ),
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<SignInSubmitCodeCommandResult>()
        assertTrue(result is ICommandResult.UnknownError)
    }
}

// SignInResendCodeCommandResult
@RunWith(Parameterized::class)
class CommandResultUtilTestSignInResendCodeCommandResult(private val resultValue: Any) {

    companion object {
        @JvmStatic
        @Parameters
        fun getSignInResendCodeCommandResults() = listOf(
            signInCodeRequiredCommandResult,
            redirectCommandResult,
            unknownErrorCommandResult
        )
    }

    @Test
    fun checkAndWrapCommandResultTypeSignInResendCodeCommandResultSuccess() {
        val commandResult = CommandResult<Any>(
            ResultStatus.COMPLETED,
            resultValue,
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<SignInResendCodeCommandResult>()
        assertEquals(resultValue.javaClass, result.javaClass)
    }

    @Test
    fun testCheckAndWrapCommandResultTypeCompletedStatusWrongType() {
        val commandResult = CommandResult<Any>(
            ResultStatus.COMPLETED,
            ResetPasswordCommandResult.Complete,
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<SignInResendCodeCommandResult>()
        assertTrue(result is ICommandResult.UnknownError)
    }

    @Test
    fun testCheckAndWrapCommandResultTypeErrorStatus() {
        val commandResult = CommandResult<Any>(
            ResultStatus.ERROR,
            ClientException(
                ERROR
            ),
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<SignInResendCodeCommandResult>()
        assertTrue(result is ICommandResult.UnknownError)
    }

    @Test
    fun testCheckAndWrapCommandResultTypeCompletedStatusWithException() {
        val commandResult = CommandResult<Any>(
            ResultStatus.COMPLETED,
            ClientException(
                ERROR
            ),
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<SignInResendCodeCommandResult>()
        assertTrue(result is ICommandResult.UnknownError)
    }
}

// SignInSubmitPasswordCommandResult
@RunWith(Parameterized::class)
class CommandResultUtilTestSignInSubmitPasswordCommandResult(private val resultValue: Any) {

    companion object {
        @JvmStatic
        @Parameters
        fun getSignInSubmitPasswordCommandResults() = listOf(
            signInCodeRequiredCommandResult,
            signInCompleteCommandResult,
            signInInvalidCredentialsCommandResult,
            redirectCommandResult,
            unknownErrorCommandResult
        )
    }

    @Test
    fun checkAndWrapCommandResultTypeSignInSubmitPasswordCommandResultSuccess() {
        val commandResult = CommandResult<Any>(
            ResultStatus.COMPLETED,
            resultValue,
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<SignInSubmitPasswordCommandResult>()
        assertEquals(resultValue.javaClass, result.javaClass)
    }

    @Test
    fun testCheckAndWrapCommandResultTypeCompletedStatusWrongType() {
        val commandResult = CommandResult<Any>(
            ResultStatus.COMPLETED,
            ResetPasswordCommandResult.Complete,
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<SignInSubmitPasswordCommandResult>()
        assertTrue(result is ICommandResult.UnknownError)
    }

    @Test
    fun testCheckAndWrapCommandResultTypeErrorStatus() {
        val commandResult = CommandResult<Any>(
            ResultStatus.ERROR,
            ClientException(
                ERROR
            ),
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<SignInSubmitPasswordCommandResult>()
        assertTrue(result is ICommandResult.UnknownError)
    }

    @Test
    fun testCheckAndWrapCommandResultTypeCompletedStatusWithException() {
        val commandResult = CommandResult<Any>(
            ResultStatus.COMPLETED,
            ClientException(
                ERROR
            ),
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<SignInSubmitPasswordCommandResult>()
        assertTrue(result is ICommandResult.UnknownError)
    }
}
//endregion

//region reset password
private val resetPasswordCodeRequiredCommandResult = ResetPasswordCommandResult.CodeRequired(
    passwordResetToken = PASSWORD_RESET_TOKEN,
    challengeChannel = CHALLENGE_TYPE,
    challengeTargetLabel = CHALLENGE_TARGET_LABEL,
    codeLength = CODE_LENGTH
)

private val resetPasswordCompleteCommandResult = ResetPasswordCommandResult.Complete

private val resetPasswordEmailNotVerifiedCommandResult = ResetPasswordCommandResult.EmailNotVerified(
    error = ERROR,
    errorDescription = ERROR_DESCRIPTION
)

private val resetPasswordIncorrectCodeCommandResult = ResetPasswordCommandResult.IncorrectCode(
    error = ERROR,
    errorDescription = ERROR_DESCRIPTION
)

private val resetPasswordPasswordNotAcceptedCommandResult = ResetPasswordCommandResult.PasswordNotAccepted(
    error = ERROR,
    errorDescription = ERROR_DESCRIPTION
)

private val resetPasswordPasswordNotSetCommandResult = ResetPasswordCommandResult.PasswordNotSet(
    error = ERROR,
    errorDescription = ERROR_DESCRIPTION
)

private val resetPasswordPasswordResetFailedCommandResult = ResetPasswordCommandResult.PasswordResetFailed(
    error = ERROR,
    errorDescription = ERROR_DESCRIPTION
)

private val resetPasswordPasswordRequiredCommandResult = ResetPasswordCommandResult.PasswordRequired(
    passwordSubmitToken = PASSWORD_SUBMIT_TOKEN
)

private val resetPasswordUserNotFoundCommandResult = ResetPasswordCommandResult.UserNotFound(
    error = ERROR,
    errorDescription = ERROR_DESCRIPTION
)

// ResetPasswordStartCommandResult
@RunWith(Parameterized::class)
class CommandResultUtilTestResetPasswordStartCommandResult(private val resultValue: Any) {

    companion object {
        @JvmStatic
        @Parameters
        fun getResetPasswordStartCommandResults() = listOf(
            resetPasswordCodeRequiredCommandResult,
            resetPasswordEmailNotVerifiedCommandResult,
            resetPasswordPasswordNotSetCommandResult,
            resetPasswordUserNotFoundCommandResult,
            redirectCommandResult,
            unknownErrorCommandResult
        )
    }

    @Test
    fun checkAndWrapCommandResultTypeResetPasswordStartCommandResultSuccess() {
        val commandResult = CommandResult<Any>(
            ResultStatus.COMPLETED,
            resultValue,
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<ResetPasswordStartCommandResult>()
        assertEquals(resultValue.javaClass, result.javaClass)
    }

    @Test
    fun testCheckAndWrapCommandResultTypeCompletedStatusWrongType() {
        val commandResult = CommandResult<Any>(
            ResultStatus.COMPLETED,
            SignUpCommandResult.Complete(signInSLT = null, expiresIn = null),
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<ResetPasswordStartCommandResult>()
        assertTrue(result is ICommandResult.UnknownError)
    }

    @Test
    fun testCheckAndWrapCommandResultTypeErrorStatus() {
        val commandResult = CommandResult<Any>(
            ResultStatus.ERROR,
            ClientException(
                ERROR
            ),
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<ResetPasswordStartCommandResult>()
        assertTrue(result is ICommandResult.UnknownError)
    }

    @Test
    fun testCheckAndWrapCommandResultTypeCompletedStatusWithException() {
        val commandResult = CommandResult<Any>(
            ResultStatus.COMPLETED,
            ClientException(
                ERROR
            ),
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<ResetPasswordStartCommandResult>()
        assertTrue(result is ICommandResult.UnknownError)
    }
}

// ResetPasswordSubmitCodeCommandResult
@RunWith(Parameterized::class)
class CommandResultUtilTestResetPasswordSubmitCodeCommandResult(private val resultValue: Any) {

    companion object {
        @JvmStatic
        @Parameters
        fun getResetPasswordStartCommandResults() = listOf(
            resetPasswordIncorrectCodeCommandResult,
            resetPasswordPasswordRequiredCommandResult,
            redirectCommandResult,
            unknownErrorCommandResult
        )
    }

    @Test
    fun checkAndWrapCommandResultTypeResetPasswordSubmitCodeCommandResultSuccess() {
        val commandResult = CommandResult<Any>(
            ResultStatus.COMPLETED,
            resultValue,
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<ResetPasswordSubmitCodeCommandResult>()
        assertEquals(resultValue.javaClass, result.javaClass)
    }

    @Test
    fun testCheckAndWrapCommandResultTypeCompletedStatusWrongType() {
        val commandResult = CommandResult<Any>(
            ResultStatus.COMPLETED,
            SignUpCommandResult.Complete(signInSLT = null, expiresIn = null),
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<ResetPasswordSubmitCodeCommandResult>()
        assertTrue(result is ICommandResult.UnknownError)
    }

    @Test
    fun testCheckAndWrapCommandResultTypeErrorStatus() {
        val commandResult = CommandResult<Any>(
            ResultStatus.ERROR,
            ClientException(
                ERROR
            ),
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<ResetPasswordSubmitCodeCommandResult>()
        assertTrue(result is ICommandResult.UnknownError)
    }

    @Test
    fun testCheckAndWrapCommandResultTypeCompletedStatusWithException() {
        val commandResult = CommandResult<Any>(
            ResultStatus.COMPLETED,
            ClientException(
                ERROR
            ),
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<ResetPasswordSubmitCodeCommandResult>()
        assertTrue(result is ICommandResult.UnknownError)
    }
}

// ResetPasswordResendCodeCommandResult
@RunWith(Parameterized::class)
class CommandResultUtilTestResetPasswordResendCodeCommandResult(private val resultValue: Any) {

    companion object {
        @JvmStatic
        @Parameters
        fun getResetPasswordStartCommandResults() = listOf(
            resetPasswordCodeRequiredCommandResult,
            redirectCommandResult,
            unknownErrorCommandResult
        )
    }

    @Test
    fun checkAndWrapCommandResultTypeResetPasswordResendCodeCommandResultSuccess() {
        val commandResult = CommandResult<Any>(
            ResultStatus.COMPLETED,
            resultValue,
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<ResetPasswordResendCodeCommandResult>()
        assertEquals(resultValue.javaClass, result.javaClass)
    }

    @Test
    fun testCheckAndWrapCommandResultTypeCompletedStatusWrongType() {
        val commandResult = CommandResult<Any>(
            ResultStatus.COMPLETED,
            SignUpCommandResult.Complete(signInSLT = null, expiresIn = null),
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<ResetPasswordResendCodeCommandResult>()
        assertTrue(result is ICommandResult.UnknownError)
    }

    @Test
    fun testCheckAndWrapCommandResultTypeErrorStatus() {
        val commandResult = CommandResult<Any>(
            ResultStatus.ERROR,
            ClientException(
                ERROR
            ),
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<ResetPasswordResendCodeCommandResult>()
        assertTrue(result is ICommandResult.UnknownError)
    }

    @Test
    fun testCheckAndWrapCommandResultTypeCompletedStatusWithException() {
        val commandResult = CommandResult<Any>(
            ResultStatus.COMPLETED,
            ClientException(
                ERROR
            ),
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<ResetPasswordResendCodeCommandResult>()
        assertTrue(result is ICommandResult.UnknownError)
    }
}

// ResetPasswordSubmitNewPasswordCommandResult
@RunWith(Parameterized::class)
class CommandResultUtilTestResetPasswordSubmitNewPasswordCommandResult(private val resultValue: Any) {

    companion object {
        @JvmStatic
        @Parameters
        fun getResetPasswordSubmitNewPasswordCommandResults() = listOf(
            resetPasswordCompleteCommandResult,
            resetPasswordPasswordNotAcceptedCommandResult,
            resetPasswordPasswordResetFailedCommandResult,
            unknownErrorCommandResult,
            resetPasswordUserNotFoundCommandResult
        )
    }

    @Test
    fun checkAndWrapCommandResultTypeResetPasswordSubmitNewPasswordCommandResultSuccess() {
        val commandResult = CommandResult<Any>(
            ResultStatus.COMPLETED,
            resultValue,
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<ResetPasswordSubmitNewPasswordCommandResult>()
        assertEquals(resultValue.javaClass, result.javaClass)
    }

    @Test
    fun testCheckAndWrapCommandResultTypeCompletedStatusWrongType() {
        val commandResult = CommandResult<Any>(
            ResultStatus.COMPLETED,
            SignUpCommandResult.Complete(signInSLT = null, expiresIn = null),
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<ResetPasswordSubmitNewPasswordCommandResult>()
        assertTrue(result is ICommandResult.UnknownError)
    }

    @Test
    fun testCheckAndWrapCommandResultTypeErrorStatus() {
        val commandResult = CommandResult<Any>(
            ResultStatus.ERROR,
            ClientException(
                ERROR
            ),
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<ResetPasswordSubmitNewPasswordCommandResult>()
        assertTrue(result is ICommandResult.UnknownError)
    }

    @Test
    fun testCheckAndWrapCommandResultTypeCompletedStatusWithException() {
        val commandResult = CommandResult<Any>(
            ResultStatus.COMPLETED,
            ClientException(
                ERROR
            ),
            null
        )

        val result = commandResult.checkAndWrapCommandResultType<ResetPasswordSubmitNewPasswordCommandResult>()
        assertTrue(result is ICommandResult.UnknownError)
    }
}
// emdregion
