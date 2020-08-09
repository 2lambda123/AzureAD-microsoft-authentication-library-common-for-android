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
package com.microsoft.identity.client.ui.automation.broker;

import android.text.TextUtils;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.test.uiautomator.UiDevice;
import androidx.test.uiautomator.UiObject;
import androidx.test.uiautomator.UiObjectNotFoundException;
import androidx.test.uiautomator.UiSelector;

import com.microsoft.identity.client.ui.automation.BuildConfig;
import com.microsoft.identity.client.ui.automation.app.App;
import com.microsoft.identity.client.ui.automation.installer.LocalApkInstaller;
import com.microsoft.identity.client.ui.automation.installer.PlayStore;
import com.microsoft.identity.client.ui.automation.interaction.PromptHandlerParameters;
import com.microsoft.identity.client.ui.automation.interaction.PromptParameter;
import com.microsoft.identity.client.ui.automation.interaction.microsoftsts.AadPromptHandler;
import com.microsoft.identity.client.ui.automation.utils.CommonUtils;
import com.microsoft.identity.client.ui.automation.utils.UiAutomatorUtils;

import org.junit.Assert;

import static androidx.test.platform.app.InstrumentationRegistry.getInstrumentation;
import static com.microsoft.identity.client.ui.automation.utils.CommonUtils.FIND_UI_ELEMENT_TIMEOUT;
import static com.microsoft.identity.client.ui.automation.utils.CommonUtils.getResourceId;

/**
 * A model for interacting with a Broker App during UI Test.
 */
public abstract class AbstractTestBroker extends App implements ITestBroker {

    public AbstractTestBroker(@NonNull final String packageName,
                              @NonNull final String appName) {
        super(packageName, appName, BuildConfig.INSTALL_SOURCE_LOCAL_APK
                .equalsIgnoreCase(BuildConfig.BROKER_INSTALL_SOURCE)
                ? new LocalApkInstaller() : new PlayStore());
    }

    @Override
    public void handleAccountPicker(@Nullable final String username) {
        final UiDevice device = UiDevice.getInstance(getInstrumentation());

        // find the object associated to this username in account picker.
        // if the username is not provided, then click on the "Use another account" option
        final UiObject accountSelected = device.findObject(new UiSelector().resourceId(
                getResourceId(getPackageName(), "account_chooser_listView")
        ).childSelector(new UiSelector().textContains(
                // This String is pulled from
                // R.string.broker_account_chooser_choose_another_account
                TextUtils.isEmpty(username) ? "Use another account" : username
        )));

        try {
            accountSelected.waitForExists(FIND_UI_ELEMENT_TIMEOUT);
            accountSelected.click();
        } catch (final UiObjectNotFoundException e) {
            Assert.fail(e.getMessage());
        }
    }

    @Override
    public void performJoinViaJoinActivity(@NonNull final String username,
                                           @NonNull final String password) {
        // Enter username
        UiAutomatorUtils.handleInput(
                CommonUtils.getResourceId(
                        getPackageName(), "UsernameET"
                ),
                username
        );

        // Click Join
        UiAutomatorUtils.handleButtonClick(
                CommonUtils.getResourceId(
                        getPackageName(), "JoinButton"
                )
        );

        final PromptHandlerParameters promptHandlerParameters = PromptHandlerParameters.builder()
                .broker(this)
                .prompt(PromptParameter.SELECT_ACCOUNT)
                .loginHint(username)
                .sessionExpected(false)
                .build();

        final AadPromptHandler aadPromptHandler = new AadPromptHandler(promptHandlerParameters);

        // Handle prompt in AAD login page
        aadPromptHandler.handlePrompt(username, password);
    }

    @Override
    public void confirmJoinInJoinActivity(@NonNull final String username) {
        final UiObject joinConfirmation = UiAutomatorUtils.obtainUiObjectWithText(
                "Workplace Joined to " + username
        );

        Assert.assertTrue(joinConfirmation.exists());

        UiAutomatorUtils.handleButtonClick(getResourceId(
                getPackageName(),
                "JoinButton"
        ));
    }

}
