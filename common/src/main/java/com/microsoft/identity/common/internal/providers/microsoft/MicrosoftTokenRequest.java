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
package com.microsoft.identity.common.internal.providers.microsoft;

import androidx.annotation.Nullable;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import com.microsoft.identity.common.internal.commands.parameters.IHasExtraParameters;
import com.microsoft.identity.common.internal.providers.oauth2.TokenRequest;

import java.util.Map;
import java.util.UUID;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.Accessors;
import lombok.experimental.SuperBuilder;

@SuperBuilder
@AllArgsConstructor
@Getter
@Setter
@Accessors(prefix = "m")
public class MicrosoftTokenRequest extends TokenRequest implements IHasExtraParameters {

    public static final String CODE_VERIFIER = "code_verifier";
    public static final String CLIENT_INFO = "client_info";
    public static final String CORRELATION_ID = "client-request-id";
    public static final String ID_TOKEN_VERSION = "itver";
    public static final String MAM_VERSION = "mamver";
    public static final String CLAIMS = "claims";
    public static final String INSTANCE_AWARE = "instance_aware";
    public static final String CLIENT_APP_NAME = "x-app-name";
    public static final String CLIENT_APP_VERSION = "x-app-ver";
    public static final String MICROSOFT_ENROLLMENT_ID = "microsoft_enrollment_id";
    public static final String DEVICE_CODE = "device_code";

    public MicrosoftTokenRequest() {
        super();
        mClientInfoEnabled = "1";
    }

    @SerializedName(CODE_VERIFIER)
    private String mCodeVerifier;

    @Expose()
    @SerializedName(CLIENT_INFO)
    private String mClientInfoEnabled;

    @Expose()
    @SerializedName(CORRELATION_ID)
    private UUID mCorrelationId;

    @Expose()
    @SerializedName(ID_TOKEN_VERSION)
    private String mIdTokenVersion;

    @Expose()
    @SerializedName(MAM_VERSION)
    private String mMamVersion;

    @Expose()
    @SerializedName(CLAIMS)
    private String mClaims;

    @Expose()
    @SerializedName(INSTANCE_AWARE)
    private String mInstanceAware;

    @Expose()
    @SerializedName(CLIENT_APP_NAME)
    private String mClientAppName;

    @Expose()
    @SerializedName(CLIENT_APP_VERSION)
    private String mClientAppVersion;

    @Expose()
    @SerializedName(MICROSOFT_ENROLLMENT_ID)
    private String mMicrosoftEnrollmentId;

    @Nullable
    @Expose()
    @SerializedName(DEVICE_CODE)
    private String mDeviceCode;

    private String mTokenScope;

    // Sent as part of headers if available, so marking it transient.
    private transient String mBrokerVersion;
}
