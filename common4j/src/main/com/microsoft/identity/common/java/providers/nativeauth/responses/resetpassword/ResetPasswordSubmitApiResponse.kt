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
package com.microsoft.identity.common.java.providers.nativeauth.responses.resetpassword

import com.google.gson.annotations.Expose
import com.google.gson.annotations.SerializedName
import com.microsoft.identity.common.java.logging.LogSession
import com.microsoft.identity.common.java.providers.nativeauth.IApiResponse
import com.microsoft.identity.common.java.providers.nativeauth.interactors.InnerError
import com.microsoft.identity.common.java.util.*
import java.net.HttpURLConnection

class ResetPasswordSubmitApiResponse(
    @Expose override var statusCode: Int,
    @Expose @SerializedName("password_reset_token") val passwordResetToken: String?,
    @Expose @SerializedName("poll_interval") val pollInterval: Int?,
    @Expose @SerializedName("error") val error: String?,
    @Expose @SerializedName("error_description") val errorDescription: String?,
    @Expose @SerializedName("error_uri") val errorUri: String?,
    @Expose @SerializedName("details") val details: List<Map<String, String>>?,
    @Expose @SerializedName("inner_errors") val innerErrors: List<InnerError>?
): IApiResponse(statusCode) {

    companion object {
        private val TAG = ResetPasswordSubmitApiResponse::class.java.simpleName
    }

    fun toResult(): ResetPasswordSubmitApiResult {
        LogSession.logMethodCall(TAG)

        return when (statusCode) {

            // Handle 400 errors
            HttpURLConnection.HTTP_BAD_REQUEST -> {
                return when {
                    error.isPasswordBanned() || error.isPasswordTooShort() || error.isPasswordTooLong() || error.isPasswordRecentlyUsed() ||
                            error.isPasswordTooWeak() -> {
                        ResetPasswordSubmitApiResult.PasswordInvalid(
                            error = error.orEmpty(),
                            errorDescription = errorDescription.orEmpty()
                        )
                    }
                    error.isExpiredToken() -> {
                        ResetPasswordSubmitApiResult.ExpiredToken(
                            error = error.orEmpty(),
                            errorDescription = errorDescription.orEmpty()
                        )
                    }
                    else -> {
                        ResetPasswordSubmitApiResult.UnknownError(
                            error = error,
                            errorDescription = errorDescription,
                            details = details
                        )
                    }
                }
            }

            // Handle success and redirect
            HttpURLConnection.HTTP_OK -> {
                ResetPasswordSubmitApiResult.SubmitSuccess(
                    passwordResetToken = passwordResetToken
                        ?: return ResetPasswordSubmitApiResult.UnknownError(
                            error = "invalid_state",
                            errorDescription = "ResetPassword /submit successful, but did not return a flow token",
                            details = details
                        ),
                    pollInterval = pollInterval
                )
            }

            // Catch uncommon status codes
            else -> {
                ResetPasswordSubmitApiResult.UnknownError(
                    error = error.orEmpty(),
                    errorDescription = errorDescription.orEmpty(),
                    details = details
                )
            }
        }
    }
}