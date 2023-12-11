// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
package com.microsoft.identity.common.nativeauth.providers.responses.signup

import com.google.gson.annotations.Expose
import com.google.gson.annotations.SerializedName
import com.microsoft.identity.common.java.logging.LogSession
import com.microsoft.identity.common.nativeauth.providers.IApiResponse
import com.microsoft.identity.common.nativeauth.providers.responses.ApiErrorResult
import com.microsoft.identity.common.nativeauth.util.isAttributeValidationFailed
import com.microsoft.identity.common.nativeauth.util.isAuthNotSupported
import com.microsoft.identity.common.nativeauth.util.isInvalidClient
import com.microsoft.identity.common.nativeauth.util.isInvalidEmail
import com.microsoft.identity.common.nativeauth.util.isInvalidParameter
import com.microsoft.identity.common.nativeauth.util.isPasswordBanned
import com.microsoft.identity.common.nativeauth.util.isPasswordRecentlyUsed
import com.microsoft.identity.common.nativeauth.util.isPasswordTooLong
import com.microsoft.identity.common.nativeauth.util.isPasswordTooShort
import com.microsoft.identity.common.nativeauth.util.isPasswordTooWeak
import com.microsoft.identity.common.nativeauth.util.isRedirect
import com.microsoft.identity.common.nativeauth.util.isUnsupportedChallengeType
import com.microsoft.identity.common.nativeauth.util.isUserAlreadyExists
import com.microsoft.identity.common.nativeauth.util.isVerificationRequired
import com.microsoft.identity.common.nativeauth.util.toAttributeList
import java.net.HttpURLConnection

/**
 * Represents the raw response from the Sign Up /start endpoint.
 * Can be converted to SignUpContinueApiResult using the provided toResult() method.
 */
data class SignUpStartApiResponse(
    @Expose override var statusCode: Int,
    @Expose @SerializedName("error") val error: String?,
    @Expose @SerializedName("error_description") val errorDescription: String?,
    @SerializedName("signup_token") val signupToken: String?,
    @Expose @SerializedName("unverified_attributes") val unverifiedAttributes: List<Map<String, String>>?,
    @Expose @SerializedName("invalid_attributes") val invalidAttributes: List<Map<String, String>>?,
    @SerializedName("details") val details: List<Map<String, String>>?,
    @Expose @SerializedName("challenge_type") val challengeType: String?,
    @Expose @SerializedName("error_codes") val errorCodes: List<Int>?
) : IApiResponse(statusCode) {

    companion object {
        private val TAG = SignUpStartApiResponse::class.java.simpleName
    }

    fun toResult(): SignUpStartApiResult {
        LogSession.logMethodCall(TAG, "${TAG}.toResult")

        return when (statusCode) {

            // Handle 400 errors
            HttpURLConnection.HTTP_BAD_REQUEST -> {
                when {
                    error.isUserAlreadyExists() -> {
                        SignUpStartApiResult.UsernameAlreadyExists(
                            error = error.orEmpty(),
                            errorDescription = errorDescription.orEmpty()
                        )
                    }
                    errorCodes?.get(0).isInvalidParameter() and (errorDescription?.isInvalidEmail() == true) -> {
                        SignUpStartApiResult.InvalidEmail(
                            error = error.orEmpty(),
                            errorDescription = errorDescription.orEmpty()
                        )
                    }
                    error.isAuthNotSupported() -> {
                        SignUpStartApiResult.AuthNotSupported(
                            error = error.orEmpty(),
                            errorDescription = errorDescription.orEmpty()
                        )
                    }
                    error.isAttributeValidationFailed() -> {
                        SignUpStartApiResult.InvalidAttributes(
                            error = error.orEmpty(),
                            errorDescription = errorDescription.orEmpty(),
                            invalidAttributes = invalidAttributes?.toAttributeList()
                                ?: return SignUpStartApiResult.UnknownError(
                                    error = ApiErrorResult.INVALID_STATE,
                                    errorDescription = "SignUp /start did not return a invalid_attributes with validation_failed error",
                                    details = details
                                )
                        )
                    }
                    error.isUnsupportedChallengeType() -> {
                        SignUpStartApiResult.UnsupportedChallengeType(
                            error = error.orEmpty(),
                            errorDescription = errorDescription.orEmpty()
                        )
                    }
                    error.isPasswordTooWeak() || error.isPasswordTooLong() || error.isPasswordTooShort()
                            || error.isPasswordBanned() || error.isPasswordRecentlyUsed() -> {
                        SignUpStartApiResult.InvalidPassword(
                            error = error.orEmpty(),
                            errorDescription = errorDescription.orEmpty(),
                        )
                    }
                    error.isVerificationRequired() -> {
                        SignUpStartApiResult.VerificationRequired(
                            signupToken = signupToken
                                ?: return SignUpStartApiResult.UnknownError(
                                    error = ApiErrorResult.INVALID_STATE,
                                    errorDescription = "SignUp /start did not return a flow token with verification_required error",
                                    details = details
                                ),
                            error = error.orEmpty(),
                            errorDescription = errorDescription.orEmpty(),
                            unverifiedAttributes = unverifiedAttributes
                                ?: return SignUpStartApiResult.UnknownError(
                                    error = ApiErrorResult.INVALID_STATE,
                                    errorDescription = "SignUp /start did not return a unverified_attributes with verification_required error",
                                    details = details
                                )
                        )
                    }
                    else -> {
                        SignUpStartApiResult.UnknownError(
                            error = error.orEmpty(),
                            errorDescription = errorDescription.orEmpty(),
                            details = details
                        )
                    }
                }
            }

            // Handle success and redirect
            HttpURLConnection.HTTP_OK -> {
                if (challengeType.isRedirect()) {
                    SignUpStartApiResult.Redirect
                }
                else {
                    SignUpStartApiResult.UnknownError(
                        error = error.orEmpty(),
                        errorDescription = errorDescription.orEmpty(),
                        details = details
                    )
                }
            }

            // Catch uncommon status codes
            else -> {
                SignUpStartApiResult.UnknownError(
                    error = error.orEmpty(),
                    errorDescription = errorDescription.orEmpty(),
                    details = details
                )
            }
        }
    }
}
