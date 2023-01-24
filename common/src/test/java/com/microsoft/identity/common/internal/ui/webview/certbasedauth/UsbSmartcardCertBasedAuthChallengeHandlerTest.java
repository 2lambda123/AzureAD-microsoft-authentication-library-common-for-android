// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
package com.microsoft.identity.common.internal.ui.webview.certbasedauth;

import static org.junit.Assert.assertNotNull;

import android.app.Activity;

import androidx.annotation.NonNull;

import com.microsoft.identity.common.java.opentelemetry.ICertBasedAuthTelemetryHelper;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

@RunWith(RobolectricTestRunner.class)
public class UsbSmartcardCertBasedAuthChallengeHandlerTest extends AbstractSmartcardCertBasedAuthChallengeHandlerTest {
    private UsbSmartcardCertBasedAuthChallengeHandler mChallengeHandler;
    final TestCertBasedAuthTelemetryHelper mTestCertBasedAuthTelemetryHelper = new TestCertBasedAuthTelemetryHelper();

    @Test
    public void testUnplugAtPickerDialog() {
        final TestUsbSmartcardCertBasedAuthManager manager = new TestUsbSmartcardCertBasedAuthManager(getMockCertList());
        setAndProcessChallengeHandler(manager);
        checkIfCorrectDialogIsShowing(TestDialog.cert_picker);
        manager.stopDiscovery(mActivity);
        checkIfCorrectDialogIsShowing(TestDialog.error);
    }

    @Test
    public void testUnplugAtPinDialog() {
        final TestUsbSmartcardCertBasedAuthManager manager = new TestUsbSmartcardCertBasedAuthManager(getMockCertList());
        setAndProcessChallengeHandler(manager);
        checkIfCorrectDialogIsShowing(TestDialog.cert_picker);
        goToPinDialog();
        manager.stopDiscovery(mActivity);
        checkIfCorrectDialogIsShowing(TestDialog.error);
    }

    //Incorrect PIN attempts before reaching limit should remain on same dialog with error message.
    //Upon no PIN attempts remaining, an error dialog should show instead.
    //Note: pin attempts remaining is initially set to 2.
    @Override
    @Test
    public void testLockedOut() {
        setAndProcessChallengeHandler(getMockCertList());
        checkIfCorrectDialogIsShowing(TestDialog.cert_picker);
        goToPinDialog();
        final SmartcardPinDialog.PositiveButtonListener pinListener = mDialogHolder.getMPinPositiveButtonListener();
        assertNotNull(pinListener);
        final char[] wrongPin = {'1', '2', '3'};
        pinListener.onClick(wrongPin);
        checkIfCorrectDialogIsShowing(TestDialog.pin);
        pinListener.onClick(wrongPin);
        checkIfCorrectDialogIsShowing(TestDialog.error);
    }

    @Override
    @Test
    public void testExceptionThrownWhenVerifyingPin() {
        setAndProcessChallengeHandler(getMockCertList());
        checkIfCorrectDialogIsShowing(TestDialog.cert_picker);
        goToPinDialog();
        final SmartcardPinDialog.PositiveButtonListener pinListener = mDialogHolder.getMPinPositiveButtonListener();
        assertNotNull(pinListener);
        final char[] exceptionPin = {'e', 'x', 'c'};
        pinListener.onClick(exceptionPin);
        checkIfCorrectDialogIsShowing(TestDialog.error);
    }

    @Override
    @Test
    public void testExceptionThrownWhenGettingKey() {
        setAndProcessChallengeHandler(getMockCertList());
        checkIfCorrectDialogIsShowing(TestDialog.cert_picker);
        goToPinDialog();
        final SmartcardPinDialog.PositiveButtonListener pinListener = mDialogHolder.getMPinPositiveButtonListener();
        assertNotNull(pinListener);
        final char[] pin = {'1', '2', '3', '4', '5', '6'};
        pinListener.onClick(pin);
        checkIfCorrectDialogIsShowing(TestDialog.error);
    }

    @Override
    protected void setAndProcessChallengeHandler(@NonNull final List<X509Certificate> certList) {
        mChallengeHandler = new UsbSmartcardCertBasedAuthChallengeHandler(
                mActivity,
                new TestUsbSmartcardCertBasedAuthManager(certList),
                mDialogHolder,
                mTestCertBasedAuthTelemetryHelper
        );
        mChallengeHandler.processChallenge(getMockClientCertRequest());
    }

    private void setAndProcessChallengeHandler(@NonNull final TestUsbSmartcardCertBasedAuthManager manager) {
        mChallengeHandler = new UsbSmartcardCertBasedAuthChallengeHandler(
                mActivity,
                manager,
                mDialogHolder,
                mTestCertBasedAuthTelemetryHelper
        );
        mChallengeHandler.processChallenge(getMockClientCertRequest());
    }

    protected class TestUsbSmartcardCertBasedAuthManager extends AbstractUsbSmartcardCertBasedAuthManager {

        private boolean mIsConnected;
        private final List<ICertDetails> mCertDetailsList;
        private int mPinAttemptsRemaining;

        public TestUsbSmartcardCertBasedAuthManager(@NonNull final List<X509Certificate> certList) {
            mIsConnected = false;
            //Attempts remaining is usually 3, but 2 attempts is all that's necessary for testing.
            mPinAttemptsRemaining = 2;
            //Convert cert list into certDetails list.
            mCertDetailsList = new ArrayList<>();
            for (X509Certificate cert : certList) {
                mCertDetailsList.add(new ICertDetails() {
                    @NonNull
                    @Override
                    public X509Certificate getCertificate() {
                        return cert;
                    }
                });
            }
        }

        @Override
        boolean startDiscovery(@NonNull Activity activity) {
            mockConnect();
            return false;
        }

        @Override
        void stopDiscovery(@NonNull Activity activity) {
            mockDisconnect();
        }

        @Override
        void requestDeviceSession(@NonNull ISessionCallback callback) {
            try {
                callback.onGetSession(new TestSmartcardSession(mCertDetailsList, mPinAttemptsRemaining, new TestSmartcardSession.ITestSessionCallback() {
                    @Override
                    public void onIncorrectAttempt() {
                        mPinAttemptsRemaining--;
                    }
                }));
            } catch (@NonNull final Exception e) {
                callback.onException(e);
            }
        }

        @Override
        boolean isDeviceConnected() {
            return mIsConnected;
        }

        @Override
        void initBeforeProceedingWithRequest(@NonNull ICertBasedAuthTelemetryHelper telemetryHelper) {

        }

        @Override
        void onDestroy(@NonNull Activity activity) {
            stopDiscovery(mActivity);
        }

        public void mockConnect() {
            mIsConnected = true;
            if (mConnectionCallback != null) {
                mConnectionCallback.onCreateConnection();
            }
        }

        public void mockDisconnect() {
            mIsConnected = false;
            if (mConnectionCallback != null) {
                mConnectionCallback.onClosedConnection();
            }
        }
    }
}
