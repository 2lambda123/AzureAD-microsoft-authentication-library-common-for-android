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
package com.microsoft.identity.common.internal.authscheme;

import androidx.annotation.NonNull;

/**
 * Abstract base class for Token-based AuthenticationSchemes.
 */
abstract class TokenAuthenticationScheme extends AuthenticationScheme {

    /**
     * The access token associated with this scheme.
     */
    private String mAccessToken;

    /**
     * Constructs a new TokenAuthenticationScheme.
     *
     * @param name THe name of this scheme.
     */
    TokenAuthenticationScheme(@NonNull final String name) {
        super(name);
    }

    /**
     * Sets the access token.
     *
     * @param accessToken The access token to set.
     */
    final void setAccessToken(@NonNull final String accessToken) {
        mAccessToken = accessToken;
    }

    /**
     * Gets the access token.
     *
     * @return The access token to get.
     */
    final String getAccessToken() {
        return mAccessToken;
    }
}
