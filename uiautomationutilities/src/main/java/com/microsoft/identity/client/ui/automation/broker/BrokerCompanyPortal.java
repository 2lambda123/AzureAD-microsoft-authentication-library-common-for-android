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

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.uiautomator.UiDevice;
import androidx.test.uiautomator.UiObject;
import androidx.test.uiautomator.UiObjectNotFoundException;
import androidx.test.uiautomator.UiSelector;

import com.microsoft.identity.client.ui.automation.TestContext;
import com.microsoft.identity.client.ui.automation.device.settings.ISettings;
import com.microsoft.identity.client.ui.automation.device.settings.SamsungSettings;
import com.microsoft.identity.client.ui.automation.installer.PlayStore;
import com.microsoft.identity.client.ui.automation.interaction.PromptHandlerParameters;
import com.microsoft.identity.client.ui.automation.interaction.PromptParameter;
import com.microsoft.identity.client.ui.automation.interaction.microsoftsts.AadPromptHandler;
import com.microsoft.identity.client.ui.automation.utils.CommonUtils;
import com.microsoft.identity.client.ui.automation.utils.UiAutomatorUtils;

import org.junit.Assert;

import java.util.Random;

import lombok.Getter;

import static com.microsoft.identity.client.ui.automation.utils.CommonUtils.FIND_UI_ELEMENT_TIMEOUT;
import static org.junit.Assert.fail;

@Getter
public class BrokerCompanyPortal extends AbstractTestBroker implements ITestBroker, IMdmAgent {

    public final static String COMPANY_PORTAL_APP_PACKAGE_NAME = "com.microsoft.windowsintune.companyportal";
    public final static String COMPANY_PORTAL_APP_NAME = "Intune Company Portal";
    public final static String COMPANY_PORTAL_APK = "CompanyPortal.apk";

    private boolean enrollmentPerformedSuccessfully;

    public BrokerCompanyPortal() {
        super(COMPANY_PORTAL_APP_PACKAGE_NAME, COMPANY_PORTAL_APP_NAME, new PlayStore());
        localApkFileName = COMPANY_PORTAL_APK;
    }

    @Override
    public void performDeviceRegistration(@NonNull final String username,
                                          @NonNull final String password) {
        enrollDevice(username, password); // enrolling device also performs device registration
    }

    @Override
    public void performSharedDeviceRegistration(@NonNull final String username,
                                                @NonNull final String password) {
        //TODO implement shared device registration for CP
        throw new UnsupportedOperationException("Not supported!");
    }

    @Nullable
    @Override
    public String obtainDeviceId() {
        throw new UnsupportedOperationException("Not supported!");
    }

    @Override
    public void enableBrowserAccess() {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public void handleFirstRun() {
        // nothing needed here
    }

    @Override
    public void enrollDevice(@NonNull final String username,
                             @NonNull final String password) {
        launch(); // launch CP app

        handleFirstRun(); // handle CP first run

        // click Sign In button on CP welcome page
        UiAutomatorUtils.handleButtonClick("com.microsoft.windowsintune.companyportal:id/sign_in_button");

        final PromptHandlerParameters promptHandlerParameters = PromptHandlerParameters.builder()
                .prompt(PromptParameter.LOGIN)
                .consentPageExpected(false)
                .expectingLoginPageAccountPicker(false)
                .sessionExpected(false)
                .loginHint(null)
                .build();

        final AadPromptHandler aadPromptHandler = new AadPromptHandler(promptHandlerParameters);

        // handle AAD login page
        aadPromptHandler.handlePrompt(username, password);

        // click the activate device admin btn
        final UiObject accessSetupScreen = UiAutomatorUtils.obtainUiObjectWithText("Access Setup");
        Assert.assertTrue(accessSetupScreen.exists());

        // click on BEGIN button to start enroll
        UiAutomatorUtils.handleButtonClick("com.microsoft.windowsintune.companyportal:id/setup_positive_button");

        // click CONTINUE to ack privacy page
        UiAutomatorUtils.handleButtonClick("com.microsoft.windowsintune.companyportal:id/ContinueButton");

        // click NEXT to ack Android system permissions requirements
        UiAutomatorUtils.handleButtonClick("com.microsoft.windowsintune.companyportal:id/bullet_list_page_forward_button");

        // grant permission
        CommonUtils.grantPackagePermission();

        // Activate CP as admin
        TestContext.getTestContext().getDevice().getSettings().activateAdmin();

        final ISettings deviceSettings = TestContext.getTestContext().getDevice().getSettings();

        // if on a Samsung device, also need to handle enrollment in Knox
        if (deviceSettings instanceof SamsungSettings) {
            ((SamsungSettings) deviceSettings).enrollInKnox();
        }

        // make sure we are on the page to complete setup
        final UiObject setupCompletePage = UiAutomatorUtils.obtainUiObjectWithResourceId(
                "com.microsoft.windowsintune.companyportal:id/setup_title"
        );

        if (!setupCompletePage.exists()) {
            // Something went wrong with enrollment. If we see a device limit reached dialog, then
            // we throw a DeviceLimitReachedException so that we the DeviceEnrollmentRecoveryRule
            // can perform cleanup and recovery for future enrollments.
            final UiObject deviceLimitReachedDialog = UiAutomatorUtils.obtainUiObjectWithResourceId(
                    "com.microsoft.windowsintune.companyportal:id/alertTitle"
            );

            if (deviceLimitReachedDialog.exists()) {
                throw new DeviceLimitReachedException(
                        "Unable to complete enrollment as device limit reached for this account.",
                        this
                );
            } else {
                // We don't see device limit issue, but the enrollment still failed due to reasons
                // that aren't immediately known
                Assert.fail("Unable to complete enrollment due to unknown reason");
            }
        }

        // click on DONE to complete setup
        UiAutomatorUtils.handleButtonClick(
                "com.microsoft.windowsintune.companyportal:id/setup_center_button"
        );

        // Enrollment has been performed successfully
        enrollmentPerformedSuccessfully = true;
    }

    @Override
    public void handleAppProtectionPolicy() {
        final UiDevice device = UiDevice.getInstance(InstrumentationRegistry.getInstrumentation());

        // get access screen
        final UiObject getAccessScreen = UiAutomatorUtils.obtainUiObjectWithText("Get Access");
        Assert.assertTrue(getAccessScreen.exists());

        // get access screen - continue
        UiAutomatorUtils.handleButtonClick("com.microsoft.windowsintune.companyportal:id/positive_button");

        // handle PIN
        final Random random = new Random();
        final int randomPin = random.nextInt(10000);

        final UiObject pinField = UiAutomatorUtils.obtainUiObjectWithResourceId(
                "com.microsoft.windowsintune.companyportal:id/pin_entry_passcodeEditView"
        );

        try {
            pinField.setText(String.valueOf(randomPin));
        } catch (UiObjectNotFoundException e) {
            fail(e.getMessage());
        }

        device.pressEnter();

        // confirm PIN

        final UiObject pinConfirmField = UiAutomatorUtils.obtainUiObjectWithResourceId(
                "com.microsoft.windowsintune.companyportal:id/pin_entry_passcodeEditView"
        );

        try {
            pinConfirmField.setText(String.valueOf(randomPin));
        } catch (UiObjectNotFoundException e) {
            fail(e.getMessage());
        }

        device.pressEnter();
    }

    private void openDevicesTab() {
        // launch CP
        launch();

        try {
            final UiDevice device = UiDevice.getInstance(InstrumentationRegistry.getInstrumentation());

            // Click Devices Tab
            final UiObject devicesTab = device.findObject(new UiSelector().description(
                    "Devices, Tab, 2 of 3"
            ).clickable(true));

            devicesTab.waitForExists(FIND_UI_ELEMENT_TIMEOUT);

            devicesTab.click();
        } catch (UiObjectNotFoundException e) {
            Assert.fail(e.getMessage());
        }
    }

    /**
     * Removes a device from Company Portal (from the devices listed in CP Devices Tab)
     */
    public void removeDevice() {
        // if enrollment failed, then Devices Tab is automatically opened for us
        if (enrollmentPerformedSuccessfully) {
            openDevicesTab();
        }

        try {
            final UiDevice uiDevice = UiDevice.getInstance(InstrumentationRegistry.getInstrumentation());

            // If Enrollment failed, then the first device on the list is in corrupted state and
            // cannot even be removed, we need to remove the second one in the list
            final UiObject deviceToRemove = uiDevice.findObject(new UiSelector()
                    .resourceId("com.microsoft.windowsintune.companyportal:id/device_list_item")
                    .index(enrollmentPerformedSuccessfully ? 0 : 1)
            );

            deviceToRemove.waitForExists(FIND_UI_ELEMENT_TIMEOUT);

            // click on the device to be removed
            deviceToRemove.click();

            // Click more options in the top right
            final UiObject threeDots = uiDevice.findObject(new UiSelector().descriptionContains(
                    "More options"
            ));

            threeDots.waitForExists(FIND_UI_ELEMENT_TIMEOUT);

            threeDots.click();

            // Select Remove from menu
            final UiObject removeBtn = UiAutomatorUtils.obtainUiObjectWithText("Remove");

            removeBtn.click();

            final UiObject removeDeviceDialog = UiAutomatorUtils.obtainUiObjectWithResourceId(
                    "com.microsoft.windowsintune.companyportal:id/alertTitle"
            );

            Assert.assertTrue(removeDeviceDialog.exists());

            // Confirm removal
            UiAutomatorUtils.handleButtonClick("android:id/button1");
        } catch (UiObjectNotFoundException e) {
            Assert.fail(e.getMessage());
        }
    }
}
