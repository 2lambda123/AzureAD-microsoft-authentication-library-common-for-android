//  Copyright (c) Microsoft Corporation.
//  All rights reserved.
//
//  This code is licensed under the MIT License.
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files(the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions :
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.
package com.microsoft.identity.internal.testutils.authorities;

import com.microsoft.identity.common.internal.authorities.AzureActiveDirectoryB2CAuthority;
import com.microsoft.identity.common.internal.logging.Logger;
import com.microsoft.identity.common.internal.providers.microsoft.microsoftsts.MicrosoftStsOAuth2Configuration;
import com.microsoft.identity.common.internal.providers.oauth2.OAuth2Strategy;
import com.microsoft.identity.internal.testutils.strategies.ResourceOwnerPasswordCredentialsTestStrategy;

public class B2CTestAuthority extends AzureActiveDirectoryB2CAuthority {

    private static final String TAG = B2CTestAuthority.class.getName();

    public B2CTestAuthority(String authorityUrl) {
        super(authorityUrl);
    }

    @Override
    public OAuth2Strategy createOAuth2Strategy() {
        final String methodName = ":createOAuth2Strategy";
        Logger.verbose(
                TAG + methodName,
                "Creating OAuth2Strategy "
        );
        MicrosoftStsOAuth2Configuration config = new MicrosoftStsOAuth2Configuration();
        config.setMultipleCloudsSupported(false);
        config.setAuthorityUrl(this.getAuthorityURL());

        // return a custom ropc test strategy to perform ropc flow for test automation
        return new ResourceOwnerPasswordCredentialsTestStrategy(config);
    }
}
