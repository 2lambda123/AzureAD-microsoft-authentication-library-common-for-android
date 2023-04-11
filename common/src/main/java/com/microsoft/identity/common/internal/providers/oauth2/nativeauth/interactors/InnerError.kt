package com.microsoft.identity.common.internal.providers.oauth2.nativeauth.interactors

import com.google.gson.annotations.SerializedName

data class InnerError(
    @SerializedName("inner_error") val innerError: String?,
    @SerializedName("error_description") val errorDescription: String?
)
