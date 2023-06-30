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
package com.microsoft.identity.common.internal.ui.webview.fido;

import java.util.List;
import java.util.Map;

import lombok.Builder;
import lombok.Getter;
import lombok.experimental.Accessors;

/**
 * An object representing a FIDO challenge.
 */

@Builder
@Getter
@Accessors (prefix = "m")
public abstract class AbstractFidoChallenge {
    /**
     * Random data string generated by the server.
     */
    private final String mChallenge;
    /**
     * The domain name of the identity provider.
     */
    private final String mRelyingPartyIdentifier;
    /**
     * Relying party's user verification preferences (required, preferred, none).
     * For AAD, this should always be "required".
     */
    private final String mUserVerificationPolicy;
    /**
     * Passkey Auth protocol version.
     */
    private final String mVersion;
    /**
     * The Url to which the client submits the response to the server's challenge.
     */
    private final String mSubmitUrl;
    /**
     * For authentication, array of allowed key types; for registration, should have one entry for requested key type.
     */
    private final List<String> mKeyTypes;
    /**
     * Server state that needs to be maintained between challenge and response.
     */
    private final String mContext;

}
