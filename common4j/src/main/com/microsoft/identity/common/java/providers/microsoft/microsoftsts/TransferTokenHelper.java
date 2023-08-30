package com.microsoft.identity.common.java.providers.microsoft.microsoftsts;

import static com.microsoft.identity.common.java.AuthenticationConstants.OAuth2Scopes.TRANSFER_TOKEN_SCOPE;

import com.microsoft.identity.common.java.authscheme.BearerAuthenticationSchemeInternal;
import com.microsoft.identity.common.java.broker.IBrokerAccount;
import com.microsoft.identity.common.java.exception.BaseException;
import com.microsoft.identity.common.java.exception.ClientException;
import com.microsoft.identity.common.java.exception.ErrorStrings;
import com.microsoft.identity.common.java.logging.Logger;
import com.microsoft.identity.common.java.providers.oauth2.OAuth2StrategyParameters;
import com.microsoft.identity.common.java.providers.oauth2.TokenRequest;
import com.microsoft.identity.common.java.providers.oauth2.TokenResult;

import java.net.URL;
import java.util.UUID;

public class TransferTokenHelper {

    private static final String TAG = TransferTokenHelper.class.getSimpleName();

    public static TokenResult redeemTransferToken(IBrokerAccount account, String clientId) throws BaseException {
        final String methodName = ":generateTransferTokens";

        try {
            final String transferToken = "M.C102_CD1.-AjpRhxw6ctcF!D0Gw6nbMrGM49WXXeSHypRSkOvt8uUTzCFrcuKQdHn2lEYIxbQ9KYO5H2nMJmR9kEcq86canN49zVe*rLfN*Pa9T74EcGmYFalhOHeKMhUg0OPX*CZuFBoLiRdC*mNQAE4E8yFZ9YRlmEYNzJx64JE!7ZPClUvwsSF!WFkzJd3TiRSXx!0YX6ENowfUVlNZPzET4ImuMrwtbCWyQcEp6!7NLTpZJG6j*tSbO0s9YlFjvNBWld5Iot8xuYIaLv4VXjgvM!V06c4$";

            final MicrosoftStsOAuth2Configuration config = new TransferTokenOAuth2Configuration();
            config.setAuthorityUrl(new URL("https://login.windows-ppe.net"));

            // Create a correlation_id for the request
            final UUID correlationId = UUID.randomUUID();

            final String redirectUri = "msal000000004018945c://mmx";

            // Create the strategy
            final OAuth2StrategyParameters strategyParameters = OAuth2StrategyParameters.builder().build();
            final MicrosoftStsOAuth2Strategy strategy = new MicrosoftStsOAuth2Strategy(config, strategyParameters);

            final TransferTokenRequest tokenRequest = new TransferTokenRequest();
            // Set the request properties
            tokenRequest.setGrantType(TokenRequest.GrantTypes.TRANSFER_TOKEN);
            tokenRequest.setClientId(clientId);
            tokenRequest.setScope(TRANSFER_TOKEN_SCOPE);
            tokenRequest.setCorrelationId(correlationId);
            tokenRequest.setRedirectUri(redirectUri);
            tokenRequest.setTransferToken(transferToken);

            TokenResult tokenResult = strategy.requestToken(tokenRequest);
            Logger.infoPII(TAG + methodName, "Get token: " + tokenResult + " for account: " + account);
            return tokenResult;
        } catch (final Exception e) {
            Logger.error(TAG + methodName, "Failed to redeem transfer token", e);
            throw new ClientException(ErrorStrings.IO_ERROR, "Failed to redeem transfer token", e);
        }
    }
    public static TokenResult generateTransferToken(IBrokerAccount account, String clientId) throws BaseException {
        final String methodName = ":generateTransferTokens";

        try {
            final String refreshToken = "M.C102_CD1.-AWWIKSpe3n*oFC8U4yAyBttaTpihtmCd53jQgvRl16tUKOoATdTcvCIUW6wNkuLnsREnvWvIfrsPCdjE4tsTrEUfCLFBSZ6d*mULrZ8Pw5QiVi2NPS!IJ7j8GK7CUWcbBpWfSlNYZYBV63Ns9Us7rbixJbZOM7EpET7MLq3xpI8FXlQZYQmafBvbv249Q8D3wIZhw2EUkjmzkDMiOQzBmf933wJQTx0AwuhImlB2dWqrAMuRFuARwt7yUQ6u0vaVPxhGtyBAkhjA93ryvHdmjGEzaFDq76Ckkcpk2nszyMNaf1lCB6EAzEYuy9UlC6KfvetyAij52kWHHtIXIb*4a5QTYhzZjhwge0IyfOhUbQ7HY*n*wvLXeHPSmnpCEXu9o3wOk2v18f9ne1HNK3v383o$";

            final MicrosoftStsOAuth2Configuration config = new TransferTokenOAuth2Configuration();
            config.setAuthorityUrl(new URL("https://login.windows-ppe.net"));

            // Create a correlation_id for the request
            final UUID correlationId = UUID.randomUUID();

            final String redirectUri = "msal000000004018945c://mmx";

            // Create the strategy
            final OAuth2StrategyParameters strategyParameters = OAuth2StrategyParameters.builder().build();
            final MicrosoftStsOAuth2Strategy strategy = new MicrosoftStsOAuth2Strategy(config, strategyParameters);

//            final MicrosoftStsTokenRequest tokenRequest =
//                    strategy.createRefreshTokenRequest(new BearerAuthenticationSchemeInternal());
            final MicrosoftStsTokenRequest tokenRequest = new TransferTokenRequest();
            // Set the request properties
            tokenRequest.setGrantType(TokenRequest.GrantTypes.REFRESH_TOKEN);
            tokenRequest.setClientId(clientId);
            tokenRequest.setScope(TRANSFER_TOKEN_SCOPE);
            tokenRequest.setCorrelationId(correlationId);
            tokenRequest.setRefreshToken(refreshToken);
            tokenRequest.setRedirectUri(redirectUri);

            TokenResult tokenResult = strategy.requestToken(tokenRequest);
            Logger.infoPII(TAG + methodName, "Get token: " + tokenResult + " for account: " + account);
            return tokenResult;
        } catch (final Exception e) {
            Logger.error(TAG + methodName, "Failed to generate transfer token", e);
            throw new ClientException(ErrorStrings.IO_ERROR, "Failed to generate transfer token", e);
        }
    }
}
