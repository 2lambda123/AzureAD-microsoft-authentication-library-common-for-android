package com.microsoft.identity.common.java.controllers.results

interface CommandResult {
    object Redirect
        :
        SignInStartCommandResult, SignInSubmitCodeCommandResult, SignInResendCodeCommandResult,
        SignInSubmitPasswordCommandResult, SignUpStartCommandResult, SignUpSubmitCodeCommandResult,
        SignUpResendCodeCommandResult, SignUpSubmitPasswordCommandResult,
        SignUpSubmitUserAttributesCommandResult,
        ResetPasswordStartCommandResult, ResetPasswordSubmitCodeCommandResult, ResetPasswordResendCodeCommandResult

    data class UnknownError(val errorCode: String?, val errorDescription: String?) :
        SignInStartCommandResult, SignInSubmitCodeCommandResult, SignInResendCodeCommandResult,
        SignInSubmitPasswordCommandResult, SignUpStartCommandResult,
        SignUpSubmitUserAttributesCommandResult,
        SignUpSubmitCodeCommandResult, SignUpResendCodeCommandResult,
        SignUpSubmitPasswordCommandResult,
        ResetPasswordStartCommandResult, ResetPasswordSubmitCodeCommandResult, ResetPasswordResendCodeCommandResult,
        ResetPasswordSubmitNewPasswordCommandResult
}
