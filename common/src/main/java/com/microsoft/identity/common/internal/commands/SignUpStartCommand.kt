package com.microsoft.identity.common.internal.commands

import com.microsoft.identity.common.internal.controllers.NativeAuthMsalController
import com.microsoft.identity.common.java.commands.parameters.nativeauth.BaseSignUpStartCommandParameters
import com.microsoft.identity.common.java.controllers.results.SignUpStartCommandResult
import com.microsoft.identity.common.java.logging.LogSession
import com.microsoft.identity.common.java.logging.Logger

class SignUpStartCommand(
    private val parameters: BaseSignUpStartCommandParameters,
    private val controller: NativeAuthMsalController,
    publicApiId: String
) : BaseNativeAuthCommand<SignUpStartCommandResult>(
    parameters,
    controller,
    publicApiId
) {

    companion object {
        private val TAG = SignUpStartCommand::class.java.simpleName
    }

    override fun execute(): SignUpStartCommandResult {
        LogSession.logMethodCall(TAG, "${TAG}.execute")

        val result = controller.signUpStart(
            parameters = parameters
        )

        Logger.info(
            TAG,
            "Returning result: $result"
        )
        return result
    }
}
