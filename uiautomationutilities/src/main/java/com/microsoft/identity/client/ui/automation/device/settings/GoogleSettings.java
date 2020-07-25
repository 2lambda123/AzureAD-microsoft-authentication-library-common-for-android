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
package com.microsoft.identity.client.ui.automation.device.settings;

import androidx.annotation.NonNull;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.uiautomator.UiDevice;
import androidx.test.uiautomator.UiObject;
import androidx.test.uiautomator.UiObjectNotFoundException;
import androidx.test.uiautomator.UiSelector;

import com.microsoft.identity.client.ui.automation.broker.ITestBroker;
import com.microsoft.identity.client.ui.automation.utils.AdbShellUtils;
import com.microsoft.identity.client.ui.automation.utils.UiAutomatorUtils;

import org.junit.Assert;

import java.util.Calendar;

import static com.microsoft.identity.client.ui.automation.utils.CommonUtils.FIND_UI_ELEMENT_TIMEOUT;
import static com.microsoft.identity.client.ui.automation.utils.UiAutomatorUtils.obtainUiObjectWithExactText;

public class GoogleSettings extends BaseSettings {

    @Override
    public void disableAdmin(@NonNull String adminName) {
        launchDeviceAdminSettingsPage();

        try {
            // scroll down the recycler view to find the list item for this admin
            final UiObject adminAppListItem = UiAutomatorUtils.obtainChildInScrollable(
                    "android:id/list",
                    adminName
            );

            // select this admin by clicking it
            assert adminAppListItem != null;
            adminAppListItem.click();

            // scroll down the recycler view to find btn to deactivate admin
            final UiObject deactivateBtn = UiAutomatorUtils.obtainChildInScrollable(
                    android.widget.ScrollView.class,
                    "Deactivate this device admin app"
            );

            // click the deactivate admin btn
            deactivateBtn.click();

            // Click confirmation
            UiAutomatorUtils.handleButtonClick("android:id/button1");
        } catch (UiObjectNotFoundException e) {
            Assert.fail(e.getMessage());
        }
    }

    @Override
    public void removeAccount(@NonNull String username) {
        launchAccountListPage();

        try {
            // find the list item associated to this account
            final UiObject account = UiAutomatorUtils.obtainChildInScrollable(
                    "com.android.settings:id/list",
                    username
            );
            // Click this account
            account.click();

            final UiObject removeAccountBtn = UiAutomatorUtils.obtainUiObjectWithResourceIdAndText(
                    "com.android.settings:id/button",
                    "Remove account"
            );

            // Click the removeAccountBtn
            removeAccountBtn.click();

            final UiObject removeAccountConfirmationDialogBtn = UiAutomatorUtils.obtainUiObjectWithResourceIdAndText(
                    "android:id/button1",
                    "Remove account"
            );

            // Click confirm in confirmation dialog
            removeAccountConfirmationDialogBtn.click();
        } catch (UiObjectNotFoundException e) {
            Assert.fail(e.getMessage());
        }
    }

    @Override
    public void addWorkAccount(ITestBroker broker, String username, String password) {
        launchAddAccountPage();

        try {
            // scroll down the recycler view to find the list item for this account type
            final UiObject workAccount = UiAutomatorUtils.obtainChildInScrollable(
                    "com.android.settings:id/list",
                    "Work account"
            );

            // Click into this account type
            workAccount.click();

            // perform Join using the supplied broker
            broker.performJoinViaJoinActivity(username, password);

            final UiDevice device =
                    UiDevice.getInstance(InstrumentationRegistry.getInstrumentation());

            // Find the cert installer and make sure it exists
            UiObject certInstaller = device.findObject(new UiSelector().packageName("com.android.certinstaller"));
            certInstaller.waitForExists(FIND_UI_ELEMENT_TIMEOUT);
            Assert.assertTrue(certInstaller.exists());

            // Confirm install cert
            UiAutomatorUtils.handleButtonClick("android:id/button1");

            // Make sure account appears in Join Activity afterwards
            broker.confirmJoinInJoinActivity(username);
        } catch (UiObjectNotFoundException e) {
            Assert.fail(e.getMessage());
        }
    }

    @Override
    public void changeDeviceTime() {
        // Disable Automatic TimeZone
        AdbShellUtils.disableAutomaticTimeZone();
        // Launch the date time settings page
        launchDateTimeSettingsPage();

        try {
            // Click the set date button
            final UiObject setDateBtn = UiAutomatorUtils.obtainUiObjectWithText("Set date");
            setDateBtn.click();

            // Make sure we see the calendar
            final UiObject datePicker = UiAutomatorUtils.obtainUiObjectWithResourceId("android:id/date_picker_header_date");
            Assert.assertTrue(datePicker.exists());

            final Calendar cal = Calendar.getInstance();

            // add one to move to next day
            cal.add(Calendar.DATE, 1);

            // this is the new date
            final int dateToSet = cal.get(Calendar.DATE);

            if (dateToSet == 1) {
                // looks we are into the next month, so let's update month here too
                UiAutomatorUtils.handleButtonClick("android:id/next");
            }

            // Click on this new date in this calendar
            UiObject specifiedDateIcon = obtainUiObjectWithExactText(
                    String.valueOf(dateToSet)
            );
            specifiedDateIcon.click();

            // Confirm setting date
            final UiObject okBtn = UiAutomatorUtils.obtainUiObjectWithText("OK");
            okBtn.click();
        } catch (UiObjectNotFoundException e) {
            Assert.fail(e.getMessage());
        }
    }

    @Override
    public void activateAdmin() {
        try {
            // scroll down the recycler view to find activate device admin btn
            final UiObject activeDeviceAdminBtn = UiAutomatorUtils.obtainChildInScrollable(
                    "Activate this device admin app"
            );

            assert activeDeviceAdminBtn != null;

            // click on activate device admin btn
            activeDeviceAdminBtn.click();
        } catch (UiObjectNotFoundException e) {
            Assert.fail(e.getMessage());
        }
    }
}
