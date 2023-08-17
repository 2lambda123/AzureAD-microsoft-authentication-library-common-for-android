package com.microsoft.identity.common.java;

import androidx.annotation.NonNull;

//Used as a wrapper for setting and accessing values through either the generated BuildConfig.java class,
//or from parameters set via the NativeAuthPublicClientApplicationConfiguration.kt file
public class BuildValues {
    //Appended to the URL constructed in NativeAuthOAuth2Configuration, used for making calls to tenants on test slices
    @NonNull
    public static String DC = BuildConfig.DC;

    //The mock API authority used for testing will be rejected by validation logic run on instantiation. This flag is used to bypass those checks in various points in the application
    @NonNull
    public static Boolean USE_REAL_AUTHORITY = BuildConfig.USE_REAL_AUTHORITY;
}
