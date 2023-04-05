package com.microsoft.identity.common.internal.providers.oauth2.nativeauth.responses.sspr.submit

import com.google.gson.annotations.SerializedName
import com.microsoft.identity.common.internal.providers.oauth2.nativeauth.IApiErrorResponse
import com.microsoft.identity.common.java.exception.ClientException

data class SsprSubmitErrorResponse(
    var statusCode: Int,
    @SerializedName("error") private val error: String?,
    @SerializedName("error_description") private val errorDescription: String?,
    @SerializedName("error_url") val errorUrl: String?,
    @SerializedName("target") val target: String?,
    @SerializedName("error_code") val errorCode: String?
) : IApiErrorResponse {
    override fun getError() = error

    override fun getErrorDescription() = errorDescription

    override fun validateRequiredFields() {
        if (error.isNullOrBlank()) {
            throw ClientException("SsprSubmitErrorResponse.error can't be null in error state")
        }
        if (getErrorDescription().isNullOrBlank()) {
            throw ClientException("SsprSubmitErrorResponse.errorDescription can't be null in error state")
        }
    }

    override fun validateOptionalFields() {}
}
