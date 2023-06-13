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
package com.microsoft.identity.common.java.providers.nativeauth

import com.microsoft.identity.common.java.exception.ClientException
import com.microsoft.identity.common.java.logging.LogSession
import com.microsoft.identity.common.java.net.HttpResponse
import com.microsoft.identity.common.java.providers.nativeauth.responses.resetpassword.ResetPasswordChallengeApiResponse
import com.microsoft.identity.common.java.providers.nativeauth.responses.resetpassword.ResetPasswordContinueApiResponse
import com.microsoft.identity.common.java.providers.nativeauth.responses.resetpassword.ResetPasswordPollCompletionApiResponse
import com.microsoft.identity.common.java.providers.nativeauth.responses.resetpassword.ResetPasswordStartApiResponse
import com.microsoft.identity.common.java.providers.nativeauth.responses.resetpassword.ResetPasswordSubmitApiResponse
import com.microsoft.identity.common.java.providers.nativeauth.responses.signin.SignInChallengeApiResponse
import com.microsoft.identity.common.java.providers.nativeauth.responses.signin.SignInInitiateApiResponse
import com.microsoft.identity.common.java.providers.nativeauth.responses.signin.SignInTokenApiResponse
import com.microsoft.identity.common.java.providers.nativeauth.responses.signup.SignUpChallengeApiResponse
import com.microsoft.identity.common.java.providers.nativeauth.responses.signup.SignUpContinueApiResponse
import com.microsoft.identity.common.java.providers.nativeauth.responses.signup.SignUpStartApiResponse
import com.microsoft.identity.common.java.util.ApiResultUtil
import com.microsoft.identity.common.java.util.ObjectMapper

class NativeAuthResponseHandler {
    private val TAG = NativeAuthResponseHandler::class.java.simpleName

    //region signup/start
    @Throws(ClientException::class)
    internal fun getSignUpStartResultFromHttpResponse(
        response: HttpResponse
    ): SignUpStartApiResponse {
        LogSession.logMethodCall(tag = TAG)

        val result = ObjectMapper.deserializeJsonStringToObject(
            response.body,
            SignUpStartApiResponse::class.java
        )
        result.statusCode = response.statusCode

        ApiResultUtil.logResponse(TAG, result)

        return result
    }
    //endregion

    //region signup/challenge
    @Throws(ClientException::class)
    internal fun getSignUpChallengeResultFromHttpResponse(
        response: HttpResponse
    ): SignUpChallengeApiResponse {
        LogSession.logMethodCall(tag = TAG)

        val result = ObjectMapper.deserializeJsonStringToObject(
            response.body,
            SignUpChallengeApiResponse::class.java
        )
        result.statusCode = response.statusCode

        ApiResultUtil.logResponse(TAG, result)

        return result
    }
    //endregion

    //region /signup/continue
    @Throws(ClientException::class)
    internal fun getSignUpContinueResultFromHttpResponse(
        response: HttpResponse
    ): SignUpContinueApiResponse {
        LogSession.logMethodCall(tag = TAG)

        val result = ObjectMapper.deserializeJsonStringToObject(
            response.body,
            SignUpContinueApiResponse::class.java
        )
        result.statusCode = response.statusCode

        ApiResultUtil.logResponse(TAG, result)

        return result
    }

    //region /oauth/v2.0/initiate
    @Throws(ClientException::class)
    internal fun getSignInInitiateResultFromHttpResponse(
        response: HttpResponse
    ): SignInInitiateApiResponse {
        LogSession.logMethodCall(tag = TAG)

        val result = ObjectMapper.deserializeJsonStringToObject(
            response.body,
            SignInInitiateApiResponse::class.java
        )
        result.statusCode = response.statusCode

        ApiResultUtil.logResponse(TAG, result)

        return result
    }
    //endregion

    //region /oauth/v2.0/challenge
    @Throws(ClientException::class)
    internal fun getSignInChallengeResultFromHttpResponse(
        response: HttpResponse
    ): SignInChallengeApiResponse {
        LogSession.logMethodCall(tag = TAG)

        val result = ObjectMapper.deserializeJsonStringToObject(
            response.body,
            SignInChallengeApiResponse::class.java
        )
        result.statusCode = response.statusCode

        ApiResultUtil.logResponse(TAG, result)

        return result
    }
    //endregion

    //region /oauth/v2.0/token
    @Throws(ClientException::class)
    internal fun getSignInTokenResultFromHttpResponse(
        response: HttpResponse
    ): SignInTokenApiResponse {
        LogSession.logMethodCall(tag = TAG)

        val result = ObjectMapper.deserializeJsonStringToObject(
            response.body,
            SignInTokenApiResponse::class.java
        )
        result.statusCode = response.statusCode

        ApiResultUtil.logResponse(TAG, result)

        return result
    }
    //endregion

    //region /resetpassword/start
    @Throws(ClientException::class)
    internal fun getResetPasswordStartApiResponseFromHttpResponse(
        response: HttpResponse
    ): ResetPasswordStartApiResponse {
        LogSession.logMethodCall(tag = TAG)

        val apiResponse = ObjectMapper.deserializeJsonStringToObject(
            response.body,
            ResetPasswordStartApiResponse::class.java
        )
        apiResponse.statusCode = response.statusCode

        ApiResultUtil.logResponse(TAG, apiResponse)

        return apiResponse
    }

    //region /resetpassword/challenge
    @Throws(ClientException::class)
    internal fun getResetPasswordChallengeApiResponseFromHttpResponse(
        response: HttpResponse
    ): ResetPasswordChallengeApiResponse {
        LogSession.logMethodCall(tag = TAG)

        val apiResponse = ObjectMapper.deserializeJsonStringToObject(
            response.body,
            ResetPasswordChallengeApiResponse::class.java
        )
        apiResponse.statusCode = response.statusCode

        ApiResultUtil.logResponse(TAG, apiResponse)

        return apiResponse
    }

    //region /resetpassword/continue
    @Throws(ClientException::class)
    internal fun getResetPasswordContinueApiResponseFromHttpResponse(
        response: HttpResponse
    ): ResetPasswordContinueApiResponse {
        LogSession.logMethodCall(tag = TAG)

        val apiResponse = ObjectMapper.deserializeJsonStringToObject(
            response.body,
            ResetPasswordContinueApiResponse::class.java
        )
        apiResponse.statusCode = response.statusCode

        ApiResultUtil.logResponse(TAG, apiResponse)
        return apiResponse
    }

    //region /resetpassword/submit
    @Throws(ClientException::class)
    internal fun getResetPasswordSubmitApiResponseFromHttpResponse(
        response: HttpResponse
    ): ResetPasswordSubmitApiResponse {
        LogSession.logMethodCall(tag = TAG)

        val apiResponse = ObjectMapper.deserializeJsonStringToObject(
            response.body,
            ResetPasswordSubmitApiResponse::class.java
        )
        apiResponse.statusCode = response.statusCode

        ApiResultUtil.logResponse(TAG, apiResponse)

        return apiResponse
    }

    //region /resetpassword/poll_completion
    @Throws(ClientException::class)
    internal fun getResetPasswordPollCompletionApiResponseFromHttpResponse(
        response: HttpResponse
    ): ResetPasswordPollCompletionApiResponse {
        LogSession.logMethodCall(tag = TAG)

        val apiResponse = ObjectMapper.deserializeJsonStringToObject(
            response.body,
            ResetPasswordPollCompletionApiResponse::class.java
        )
        apiResponse.statusCode = response.statusCode

        ApiResultUtil.logResponse(TAG, apiResponse)

        return apiResponse
    }
}
