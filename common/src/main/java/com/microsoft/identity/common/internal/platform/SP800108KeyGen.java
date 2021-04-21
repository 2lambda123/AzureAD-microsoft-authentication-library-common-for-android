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
package com.microsoft.identity.common.internal.platform;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import lombok.NonNull;

/**
 * This class is a key derivation function for SP800 108 key generation.
 */
public class SP800108KeyGen {

    public static final byte[] BIG_ENDIAN_INT_256 = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(256).array();

    /**]
     * Generate a derived key given a starting key.
     * @param key the basis for the key material.
     * @param label a label for the key.
     * @param ctx the key context.
     * @return a derived key.
     * @throws IOException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     */
    public static byte[] generateDerivedKey(@NonNull final byte[] key, @NonNull final byte[] label, @NonNull final byte[] ctx)
            throws IOException, InvalidKeyException, NoSuchAlgorithmException {
        if (ctx == null) {
            return null;
        }
        final ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.write(label);
        stream.write(0x0);
        stream.write(ctx);

        stream.write(BIG_ENDIAN_INT_256);

        byte[] pbDerivedKey = constructNewKey(key, stream.toByteArray());
        return Arrays.copyOf(pbDerivedKey, 32);
    }

    private static byte[] constructNewKey(byte[] keyDerivationKey, byte[] fixedInput)
            throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        byte ctr;
        byte[] cHMAC;
        byte[] keyDerivated;
        byte[] dataInput;

        int len;
        int numCurrentElements;
        int numCurrentElementsBytes;
        int outputSizeBit = 256;

        numCurrentElements = 0;
        ctr = 1;
        keyDerivated = new byte[outputSizeBit / 8];
        final SecretKeySpec keySpec = new SecretKeySpec(keyDerivationKey, "HmacSHA256");
        final Mac hmacSHA256 = Mac.getInstance("HmacSHA256");

        do {
            dataInput = updateDataInput(ctr, fixedInput);
            hmacSHA256.reset();
            hmacSHA256.init(keySpec);
            hmacSHA256.update(dataInput);
            cHMAC = hmacSHA256.doFinal();
            if (256 >= outputSizeBit) {
                len = outputSizeBit;
            } else {
                len = Math.min(256, outputSizeBit - numCurrentElements);
            }

            numCurrentElementsBytes = numCurrentElements / 8;
            System.arraycopy(cHMAC, 0, keyDerivated, numCurrentElementsBytes, 32);
            numCurrentElements = numCurrentElements + len;
            ctr++;
        } while (numCurrentElements < outputSizeBit);
        return keyDerivated;
    }

    private static byte[] updateDataInput(final byte ctr, @NonNull final byte[] fixedInput) throws IOException {
        final ByteArrayOutputStream tmpFixedInput = new ByteArrayOutputStream(fixedInput.length + 4);
        tmpFixedInput.write(ctr >>> 24);
        tmpFixedInput.write(ctr >>> 16);
        tmpFixedInput.write(ctr >>> 8);
        tmpFixedInput.write(ctr);

        tmpFixedInput.write(fixedInput);
        return tmpFixedInput.toByteArray();
    }
}
