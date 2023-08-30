package com.microsoft.identity.common.java.providers.microsoft.microsoftsts;

import com.microsoft.identity.common.java.logging.Logger;
import com.microsoft.identity.common.java.util.CommonURIBuilder;

import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;

public class TransferTokenOAuth2Configuration extends MicrosoftStsOAuth2Configuration {
    private static final String TAG = TransferTokenOAuth2Configuration.class.getSimpleName();

    @Override
    public URL getTokenEndpoint() {
        final String methodName = ":getEndpointUrlFromRootAndSuffix";
        try {
            final CommonURIBuilder builder = new CommonURIBuilder(getAuthorityUrl().toString());
            builder.setPathSegments("consumers", "oauth2", "token");
            builder.addParameterIfAbsent("api-version", "2.0");
            return builder.build().toURL();
        } catch (final URISyntaxException | MalformedURLException e) {
            Logger.error(
                    TAG + methodName,
                    "Unable to create URL from provided root and suffix.",
                    null);
            Logger.errorPII(
                    TAG + methodName,
                    e.getMessage() +
                            " Unable to create URL from provided root and suffix." +
                            " root = " + getAuthorityUrl().toString(),
                    e);
        }
        return null;
    }
}
