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
import androidx.annotation.Nullable;

import com.google.gson.annotations.SerializedName;
import com.microsoft.identity.common.internal.logging.Logger;
import com.microsoft.identity.common.internal.util.StringUtil;

import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public abstract class RequestTelemetry implements IRequestTelemetry {

    private final static String TAG = RequestTelemetry.class.getSimpleName();

    @SerializedName(SchemaConstants.SCHEMA_VERSION_KEY)
    private String mSchemaVersion;

    @SerializedName("platform_telemetry")
    private ConcurrentMap<String, String> mPlatformTelemetry;

    RequestTelemetry(@NonNull final String schemaVersion) {
        mSchemaVersion = schemaVersion;
        mPlatformTelemetry = new ConcurrentHashMap<>();
    }

    private boolean isPlatformTelemetryField(final String key) {
        if (this instanceof CurrentRequestTelemetry) {
            return SchemaConstants.isCurrentPlatformField(key);
        } else if (this instanceof LastRequestTelemetry) {
            return SchemaConstants.isLastPlatformField(key);
        } else {
            return false;
        }
    }

    final void putInPlatformTelemetry(final String key, final String value) {
        if (isPlatformTelemetryField(key)) {
            mPlatformTelemetry.putIfAbsent(key, value);
        }
    }

    String getSchemaVersion() {
        return mSchemaVersion;
    }

    @Override
    public String getCompleteHeaderString() {
        final String methodName = ":getCompleteHeaderString";
        if (StringUtil.isEmpty(mSchemaVersion)) {
            Logger.verbose(
                    TAG + methodName,
                    "SCHEMA_VERSION is null or empty. " +
                            "Telemetry Header String cannot be formed."
            );

            return null;
        }

        return mSchemaVersion + "|" + this.getHeaderStringForFields() + "|" + getPlatformTelemetryHeaderString();
    }

    private String getPlatformTelemetryHeaderString() {
        final String[] platformFields;

        if (this instanceof CurrentRequestTelemetry) {
            platformFields = SchemaConstants.getCurrentRequestPlatformFields();
        } else {
            platformFields = SchemaConstants.getLastRequestPlatformFields();
        }

        return getHeaderStringForFields(platformFields, mPlatformTelemetry);
    }

    /**
     * This method loops over provided telemetry fields and creates a header string for those fields.
     * It is important to ensure that the fields array passed to this method is in the correct order,
     * as determined in {@link SchemaConstants}.
     * Failure to do so will return a malformed header string.
     *
     * @param fields    The fields that need to be included in the header string
     * @param telemetry A HashMap of telemetry data that maps keys (fields) to their values
     * @return a telemetry header string composed from provided telemetry fields and values
     */
    @NonNull
    // This only being used to compute the platform telemetry header string
    String getHeaderStringForFields(@Nullable final String[] fields, @Nullable final Map<String, String> telemetry) {
        if (fields == null || telemetry == null) {
            return "";
        }

        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < fields.length; i++) {
            final String key = fields[i];
            final String value = telemetry.get(key);
            final String compliantValueString = TelemetryUtils.getSchemaCompliantString(value);
            sb.append(compliantValueString);
            if (i != fields.length - 1) {
                sb.append(',');
            }
        }

        return sb.toString();
    }

    String getHeaderStringForFields(Collection fields) {
        if (fields == null) {
            return "";
        }

        return getHeaderStringForFields(fields.toArray());
    }

    private String getHeaderStringForFields(Object[] fields) {
        if (fields == null) {
            return "";
        }

        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < fields.length; i++) {
            final String val = TelemetryUtils.getSchemaCompliantString(fields[i].toString());
            sb.append(val);
            if (i != fields.length - 1) {
                sb.append(',');
            }
        }

        return sb.toString();
    }

    @Override
    public RequestTelemetry derive(@NonNull final RequestTelemetry requestTelemetry) {
        // grab whatever platform fields we can from current request
        for (final Map.Entry<String, String> entry : mPlatformTelemetry.entrySet()) {
            this.putInPlatformTelemetry(entry.getKey(), entry.getValue());
        }

        return this;
    }
}
