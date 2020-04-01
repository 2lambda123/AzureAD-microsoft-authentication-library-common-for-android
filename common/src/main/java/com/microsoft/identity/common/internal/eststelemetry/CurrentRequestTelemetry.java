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
package com.microsoft.identity.common.internal.eststelemetry;

import androidx.annotation.NonNull;

public class CurrentRequestTelemetry extends RequestTelemetry implements ICurrentTelemetry {

    private String mApiId;
    private boolean mForceRefresh;

    CurrentRequestTelemetry() {
        super(SchemaConstants.CURRENT_SCHEMA_VERSION);
    }

    String getApiId() {
        return mApiId;
    }

    boolean getForceRefresh() {
        return mForceRefresh;
    }

    @Override
    public String getHeaderStringForFields() {
        return TelemetryUtils.getSchemaCompliantString(mApiId) + "," +
                TelemetryUtils.getSchemaCompliantStringFromBoolean(mForceRefresh);

    }

    @Override
    public void put(@NonNull final String key, @NonNull final String value) {
        switch (key) {
            case SchemaConstants.Key.API_ID:
                mApiId = value;
                break;
            case SchemaConstants.Key.FORCE_REFRESH:
                mForceRefresh = TelemetryUtils.getBooleanFromSchemaString(value);
                break;
            default:
                putInPlatformTelemetry(key, value);
                break;
        }
    }
}
