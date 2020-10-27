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
package com.microsoft.identity.common.internal.cache;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.text.TextUtils;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.microsoft.identity.common.WarningType;
import com.microsoft.identity.common.adal.internal.cache.IStorageHelper;
import com.microsoft.identity.common.adal.internal.util.StringExtensions;
import com.microsoft.identity.common.internal.logging.Logger;

import java.io.Closeable;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * Convenience class for accessing {@link SharedPreferences}.
 */
public class SharedPreferencesFileManager implements ISharedPreferencesFileManager {

    private static final String TAG = SharedPreferencesFileManager.class.getSimpleName();

    private final String mSharedPreferencesFileName;
    private final SharedPreferences mSharedPreferences;
    private final IStorageHelper mStorageHelper;

    /**
     * Constructs an instance of SharedPreferencesFileManager.
     * The default operating mode is {@link Context#MODE_PRIVATE}
     *
     * @param context Interface to global information about an application environment.
     * @param name    The desired {@link android.content.SharedPreferences} file. It will be created
     *                if it does not exist.
     */
    public SharedPreferencesFileManager(
            final Context context,
            final String name) {
        Logger.verbose(TAG, "Init: " + TAG);
        mSharedPreferencesFileName = name;
        mSharedPreferences = context.getSharedPreferences(name, Context.MODE_PRIVATE);
        mStorageHelper = null;
    }

    /**
     * Constructs an instance of SharedPreferencesFileManager.
     *
     * @param context       Interface to global information about an application enviroment.
     * @param name          The desired {@link SharedPreferences} file. It will be created
     *                      if it does not exist.
     * @param operatingMode Operating mode {@link Context#getSharedPreferences(String, int)}.
     */
    public SharedPreferencesFileManager(
            final Context context,
            final String name,
            final int operatingMode) {
        Logger.verbose(TAG, "Init with operating mode: " + TAG);
        mSharedPreferencesFileName = name;
        mSharedPreferences = context.getSharedPreferences(name, operatingMode);
        mStorageHelper = null;
    }

    /**
     * Constructs an instance of SharedPreferencesFileManager.
     * The default operating mode is {@link Context#MODE_PRIVATE}
     *
     * @param context       Interface to global information about an application environment.
     * @param name          The desired {@link android.content.SharedPreferences} file. It will be created
     *                      if it does not exist.
     * @param storageHelper The {@link IStorageHelper} to handle encryption/decryption of values.
     */
    public SharedPreferencesFileManager(
            final Context context,
            final String name,
            final IStorageHelper storageHelper) {
        Logger.verbose(TAG, "Init with storage helper:  " + TAG);
        mSharedPreferencesFileName = name;
        mSharedPreferences = context.getSharedPreferences(name, Context.MODE_PRIVATE);
        mStorageHelper = storageHelper;
    }

    /**
     * Constructs an instance of SharedPreferencesFileManager.
     *
     * @param context       Interface to global information about an application enviroment.
     * @param name          The desired {@link SharedPreferences} file. It will be created
     *                      if it does not exist.
     * @param operatingMode Operating mode {@link Context#getSharedPreferences(String, int)}.
     * @param storageHelper The {@link IStorageHelper} to handle encryption/decryption of values.
     */
    public SharedPreferencesFileManager(
            final Context context,
            final String name,
            final int operatingMode,
            final IStorageHelper storageHelper) {
        Logger.verbose(TAG, "Init with operating mode and storage helper " + TAG);
        mSharedPreferencesFileName = name;
        mSharedPreferences = context.getSharedPreferences(name, operatingMode);
        mStorageHelper = storageHelper;
    }

    @Override
    public final void putString(
            final String key,
            final String value) {
        final SharedPreferences.Editor editor = mSharedPreferences.edit();

        if (null == mStorageHelper) {
            editor.putString(key, value);
        } else {
            final String encryptedValue = encrypt(value);
            editor.putString(key, encryptedValue);
        }

        editor.apply();
    }

    @Override
    @Nullable
    public final String getString(final String key) {
        String restoredValue = mSharedPreferences.getString(key, null);

        if (null != mStorageHelper && !StringExtensions.isNullOrBlank(restoredValue)) {
            restoredValue = decrypt(restoredValue);

            if (StringExtensions.isNullOrBlank(restoredValue)) {
                logWarningAndRemoveKey(key);
            }
        }

        return restoredValue;
    }

    @Override
    public void putLong(final String key, final long value) {
        putString(key, String.valueOf(value));
    }

    @Override
    public long getLong(final String key) {
        final String result = getString(key);

        if (!TextUtils.isEmpty(result)) {
            return Long.parseLong(result);
        }

        return 0;
    }

    private void logWarningAndRemoveKey(String key) {
        Logger.warn(
                TAG,
                "Failed to decrypt value! "
                        + "This usually signals an issue with KeyStore or the provided SecretKeys."
        );

        remove(key);
    }

    @Override
    public final String getSharedPreferencesFileName() {
        return mSharedPreferencesFileName;
    }

    @Override
    public final Map<String, String> getAll() {

        // Suppressing unchecked warnings due to casting Map<String,?> to Map<String,String>
        @SuppressWarnings(WarningType.unchecked_warning)
        final Map<String, String> entries = (Map<String, String>) mSharedPreferences.getAll();

        if (null != mStorageHelper) {
            final Iterator<Map.Entry<String, String>> iterator = entries.entrySet().iterator();

            while (iterator.hasNext()) {
                final Map.Entry<String, String> entry = iterator.next();
                final String decryptedValue = decrypt(entry.getValue());

                if (TextUtils.isEmpty(decryptedValue)) {
                    logWarningAndRemoveKey(entry.getKey());
                    iterator.remove();
                    continue;
                }

                entry.setValue(decryptedValue);
            }
        }

        return entries;
    }

    @Override
    public final boolean contains(final String key) {
        return !TextUtils.isEmpty(getString(key));
    }

    @Override
    public final void clear() {
        final SharedPreferences.Editor editor = mSharedPreferences.edit();
        editor.clear();
        editor.apply();
    }

    /**
     * @return an editing view of this shared preferences file.  It must be closed.
     */
    public ISharedPreferencesFileManager editor() {
        final SharedPreferencesFileManager mgr = this;
        final SharedPreferences.Editor editor = mSharedPreferences.edit();
        return new ISharedPreferencesFileManager() {
            boolean blank = false;
            final Map<String, Object> writtenValues = new HashMap<>();
            @Override
            public void putString(final String key, final String value) {
                writtenValues.put(key, value);
                editor.putString(key, value);
            }

            @Override
            public String getString(final String key) {
                boolean contained = writtenValues.containsKey(key);
                String value = (String) writtenValues.get(key);
                return (value != null && contained) || blank ? value : mgr.getString(key);
            }

            @Override
            public void putLong(final String key, final long value) {
                writtenValues.put(key, value);
                editor.putLong(key, value);
            }

            @Override
            public long getLong(final String key) {
                boolean contained = writtenValues.containsKey(key);
                Long value = (Long) writtenValues.get(key);
                return (value != null && contained) || blank ? value : mgr.getLong(key);
            }

            @Override
            public String getSharedPreferencesFileName() {
                return mSharedPreferencesFileName;
            }

            @Override
            public Map<String, String> getAll() {
                Map<String, String> retMap = new HashMap<String, String>();
                for (Map.Entry<String, String> e : mgr.getAll().entrySet()) {
                    if (writtenValues.containsKey(e.getKey())) {
                        if(writtenValues.get(e.getKey()) != null) {
                            retMap.put(e.getKey(), (String) writtenValues.get(e.getKey()));
                        }
                    } else {
                        if (!blank) {
                            retMap.put(e.getKey(), e.getValue());
                        }
                    }
                }
                return retMap;
            }

            @Override
            public boolean contains(final String key) {
                return (writtenValues.containsKey(key) && writtenValues.get(key) != null) || (!blank && mgr.contains(key));
            }

            @Override
            public void clear() {
                blank = true;
                writtenValues.clear();
                editor.clear();
            }

            @Override
            public void remove(final String key) {
                writtenValues.put(key, null);
                editor.remove(key);
            }

            /**
             * Close this editor.
             * @return true if the editor writes succeed.
             */
            public boolean close() {
                return editor.commit();
            }
        };
    }
    @Override
    public void remove(final String key) {
        Logger.info(
                TAG,
                "Removing cache key"
        );

        final SharedPreferences.Editor editor = mSharedPreferences.edit();
        editor.remove(key);
        editor.apply();

        Logger.infoPII(
                TAG,
                "Removed cache key ["
                        + key
                        + "]"
        );
    }

    @Nullable
    private String encrypt(@NonNull final String clearText) {
        return encryptDecryptInternal(clearText, true);
    }

    @Nullable
    private String decrypt(@NonNull final String encryptedBlob) {
        return encryptDecryptInternal(encryptedBlob, false);
    }

    @Nullable
    private String encryptDecryptInternal(
            @NonNull final String inputText,
            final boolean encrypt) {
        final String methodName = "encryptDecryptInternal";

        String result;
        try {
            result = encrypt
                    ? mStorageHelper.encrypt(inputText)
                    : mStorageHelper.decrypt(inputText);
        } catch (GeneralSecurityException | IOException e) {
            Logger.error(
                    TAG + ":" + methodName,
                    "Failed to " + (encrypt ? "encrypt" : "decrypt") + " value",
                    encrypt
                            ? null // If we failed to encrypt, don't log the error as it may contain a token
                            : e // If we failed to decrypt, we couldn't see that secret value so log the error
            );

            // TODO determine if an Exception should be thrown here...
            result = null;
        }

        return result;
    }

}
