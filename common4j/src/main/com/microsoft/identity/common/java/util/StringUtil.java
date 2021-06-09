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
package com.microsoft.identity.common.java.util;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

import edu.umd.cs.findbugs.annotations.Nullable;
import lombok.NonNull;

public class StringUtil {
    private static String TAG = StringUtil.class.getSimpleName();

    /**
     * The constant ENCODING_UTF8.
     */
    public static final String ENCODING_UTF8 = "UTF-8";

    /**
     * Checks if string is null or empty.
     *
     * @param message String to check for null or blank.
     * @return true, if the string is null or blank.
     */
    public static boolean isNullOrEmpty(String message) {
        return message == null || message.trim().length() == 0;
    }

    /**
     * Perform URL decode on the given source.
     *
     * @param source The String to decode for.
     * @return The decoded string.
     * @throws UnsupportedEncodingException If encoding is not supported.
     */
    public static String urlFormDecode(final String source) throws UnsupportedEncodingException {
        if (isNullOrEmpty(source)) {
            return "";
        }

        return URLDecoder.decode(source, ENCODING_UTF8);
    }
}
