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
import androidx.annotation.Nullable;

import com.google.gson.annotations.SerializedName;
import com.microsoft.identity.common.exception.ClientException;
import com.microsoft.identity.common.internal.platform.Device;
import com.microsoft.identity.common.internal.util.IClockSkewManager;

import java.net.URL;

import static com.microsoft.identity.common.internal.authscheme.PopAuthenticationSchemeInternal.SerializedNames.CLIENT_CLAIMS;
import static com.microsoft.identity.common.internal.authscheme.PopAuthenticationSchemeInternal.SerializedNames.HTTP_METHOD;
import static com.microsoft.identity.common.internal.authscheme.PopAuthenticationSchemeInternal.SerializedNames.NONCE;
import static com.microsoft.identity.common.internal.authscheme.PopAuthenticationSchemeInternal.SerializedNames.URL;

/**
 * Internal representation of PoP Authentication Scheme.
 */
public class PopAuthenticationSchemeInternal
        extends TokenAuthenticationScheme
        implements IPoPAuthenticationSchemeParams {

    private static final long serialVersionUID = 788393037295696358L;

    public static final class SerializedNames {
        public static final String HTTP_METHOD = "http_method";
        public static final String URL = "url";
        public static final String NONCE = "nonce";
        public static final String CLIENT_CLAIMS = "client_claims";
    }

    /**
     * The name of this auth scheme as supplied in the Authorization header value.
     */
    public static final String SCHEME_POP = "PoP";

    // Transient because this class maintains a reference to a Context
    private transient IClockSkewManager mClockSkewManager;

    @SerializedName(HTTP_METHOD)
    private String mHttpMethod;

    @SerializedName(URL)
    private URL mUrl;

    @SerializedName(NONCE)
    private String mNonce;

    @SerializedName(CLIENT_CLAIMS)
    private String mClientClaims;

    /**
     * Constructor for gson use.
     */
    PopAuthenticationSchemeInternal() {
        super(SCHEME_POP);
    }

    @Deprecated
    public PopAuthenticationSchemeInternal(@NonNull final IClockSkewManager clockSkewManager,
                                           @Nullable final String httpMethod,
                                           @NonNull final URL url,
                                           @Nullable final String nonce) {
        super(SCHEME_POP);
        mClockSkewManager = clockSkewManager;
        mHttpMethod = httpMethod;
        mUrl = url;
        mNonce = nonce;
    }

    public PopAuthenticationSchemeInternal(@NonNull final IClockSkewManager clockSkewManager,
                                           @Nullable final String httpMethod,
                                           @NonNull final URL url,
                                           @Nullable final String nonce,
                                           @Nullable final String clientClaims) {
        super(SCHEME_POP);
        mClockSkewManager = clockSkewManager;
        mHttpMethod = httpMethod;
        mUrl = url;
        mNonce = nonce;
        mClientClaims = clientClaims;
    }

    /**
     * This constructor intended to be used when this class is acting as a DTO between
     * MSAL -> Broker. Because no {@link IClockSkewManager} is supplied, functions related to access
     * token signing cannot be used.
     *
     * @param httpMethod
     * @param url
     * @param nonce
     * @param clientClaims
     */
    public PopAuthenticationSchemeInternal(@Nullable final String httpMethod,
                                           @NonNull final URL url,
                                           @Nullable final String nonce,
                                           @Nullable final String clientClaims) {
        super(SCHEME_POP);
        mClockSkewManager = null;
        mHttpMethod = httpMethod;
        mUrl = url;
        mNonce = nonce;
        mClientClaims = clientClaims;
    }

    @Override
    public String getAccessTokenForScheme(@NonNull final String accessToken) throws ClientException {
        if (null == mClockSkewManager) {
            // Shouldn't happen, would indicate a development-time bug.
            throw new RuntimeException("IClockSkewManager not initialized.");
        }

        final long ONE_SECOND_MILLIS = 1000L;
        final long timestampMillis = mClockSkewManager.getAdjustedReferenceTime().getTime();

        return Device
                .getDevicePoPManagerInstance()
                .mintSignedAccessToken(
                        getHttpMethod(),
                        timestampMillis / ONE_SECOND_MILLIS,
                        getUrl(),
                        accessToken,
                        getNonce(),
                        getClientClaims()
                );
    }

    public void setClockSkewManager(@NonNull final IClockSkewManager clockSkewManager) {
        mClockSkewManager = clockSkewManager;
    }

    @Override
    @Nullable
    public String getHttpMethod() {
        return mHttpMethod;
    }

    @Override
    public URL getUrl() {
        return mUrl;
    }

    @Override
    public String getClientClaims() {
        return mClientClaims;
    }

    @Override
    @Nullable
    public String getNonce() {
        return mNonce;
    }
}
