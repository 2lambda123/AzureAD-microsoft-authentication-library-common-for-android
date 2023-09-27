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

import com.microsoft.identity.common.java.BuildConfig
import com.microsoft.identity.common.java.BuildValues
import com.microsoft.identity.common.java.logging.LogSession
import com.microsoft.identity.common.java.logging.Logger
import com.microsoft.identity.common.java.providers.microsoft.microsoftsts.MicrosoftStsOAuth2Configuration
import com.microsoft.identity.common.java.util.UrlUtil
import java.net.MalformedURLException
import java.net.URISyntaxException
import java.net.URL

/**
 * NativeAuthOAuth2Configuration stores the parameters used for creating various Native Auth APIs
 * for Signup, SignIn and SSPR scenarios. This class also provides helper methods to generate urls
 * for those scenarios.
 */
class NativeAuthOAuth2Configuration(
    private val authorityUrl: URL,
    val clientId: String,
    val challengeType: String,
    // Need this to decide whether or not to return mock api authority or actual authority supplied in configuration
    // Turn this on if you plan to use web auth and/or open id configuration
    val useRealAuthority: Boolean = BuildValues.shouldUseRealAuthority()
) : MicrosoftStsOAuth2Configuration() {

    private val TAG = NativeAuthOAuth2Configuration::class.java.simpleName

    override fun getAuthorityUrl(): URL {
        return if (useRealAuthority) {
            authorityUrl
        } else {
            // TODO return real authorityUrl once we move away from using mock APIs
            URL("https://native-ux-mock-api.azurewebsites.net/lumonconvergedps.onmicrosoft.com")
        }
    }

    private fun getEndpointUrlFromRootAndTenantAndSuffix(root: URL, endpointSuffix: String): URL {
        LogSession.logMethodCall(TAG, "${TAG}.getEndpointUrlFromRootAndTenantAndSuffix")
        return try {
            if (BuildValues.getDC().isNotEmpty()) {
                UrlUtil.appendPathToURL(root, endpointSuffix, true, "dc=${BuildValues.getDC()}")
            } else {
                UrlUtil.appendPathToURL(root, endpointSuffix)
            }
        } catch (e: URISyntaxException) {
            Logger.error(TAG, "appendPathToURL failed", e)
            throw e
        } catch (e: MalformedURLException) {
            Logger.error(TAG, "appendPathToURL failed", e)
            throw e
        }
    }
}
