package com.microsoft.identity.common.java.providers.microsoft.microsoftsts;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;

@Setter
@Getter
@Accessors(prefix = "m")
public class TransferTokenRequest extends MicrosoftStsTokenRequest {
    @Expose()
    @SerializedName("transfer_token")
    private String mTransferToken;
}
