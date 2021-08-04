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
package com.microsoft.identity.common.internal.platform;

import static com.microsoft.identity.common.adal.internal.AuthenticationConstants.Broker.COMPANY_PORTAL_APP_PACKAGE_NAME;

import android.app.Activity;
import android.app.ActivityManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;

import com.microsoft.identity.common.adal.internal.net.DefaultConnectionService;
import com.microsoft.identity.common.internal.broker.BrokerValidator;
import com.microsoft.identity.common.internal.broker.IntuneMAMEnrollmentIdGateway;
import com.microsoft.identity.common.internal.commands.InteractiveTokenCommand;
import com.microsoft.identity.common.internal.ui.webview.WebViewUtil;
import com.microsoft.identity.common.java.commands.ICommand;
import com.microsoft.identity.common.java.commands.parameters.InteractiveTokenCommandParameters;
import com.microsoft.identity.common.java.exception.ClientException;
import com.microsoft.identity.common.java.exception.ErrorStrings;
import com.microsoft.identity.common.java.logging.Logger;
import com.microsoft.identity.common.java.util.IPlatformUtil;

import edu.umd.cs.findbugs.annotations.Nullable;
import lombok.AllArgsConstructor;
import lombok.NonNull;

@AllArgsConstructor
public class AndroidPlatformUtil implements IPlatformUtil {
    private static final String TAG = AndroidPlatformUtil.class.getSimpleName();

    @NonNull
    private final Context mContext;

    @Nullable
    private final Activity mActivity;

    @Nullable
    @Override
    public String getInstalledCompanyPortalVersion() {
        try {
            final PackageInfo packageInfo =
                    mContext.getPackageManager().getPackageInfo(COMPANY_PORTAL_APP_PACKAGE_NAME, 0);
            return packageInfo.versionName;
        } catch (final PackageManager.NameNotFoundException e) {
            // CP is not installed. No need to do anything.
        }

        return null;
    }

    public void throwIfNetworkNotAvailable(final boolean performPowerOptimizationCheck)
            throws ClientException {

        final DefaultConnectionService connectionService = new DefaultConnectionService(mContext);

        if (performPowerOptimizationCheck && connectionService.isNetworkDisabledFromOptimizations()) {
            throw new ClientException(
                    ErrorStrings.NO_NETWORK_CONNECTION_POWER_OPTIMIZATION,
                    "Connection is not available to refresh token because power optimization is "
                            + "enabled. And the device is in doze mode or the app is standby");
        }

        if (!connectionService.isConnectionAvailable()) {
            throw new ClientException(
                    ErrorStrings.DEVICE_NETWORK_NOT_AVAILABLE,
                    "Connection is not available to refresh token");
        }
    }

    @Override
    public void removeCookiesFromWebView() {
        WebViewUtil.removeCookiesFromWebView(mContext);
    }

    @Override
    public boolean isValidCallingApp(@NonNull String redirectUri, @NonNull String packageName) {
        return BrokerValidator.isValidBrokerRedirect(redirectUri, mContext, packageName);
    }

    @Override
    @Nullable
    public String getEnrollmentId(@NonNull final String userId, @NonNull final String packageName) {
        return IntuneMAMEnrollmentIdGateway
                .getInstance().getEnrollmentId(
                        mContext,
                        userId,
                        packageName
                );
    }

    @Override
    public void onReturnCommandResult(@NonNull ICommand<?> command) {
        optionallyReorderTasks(command);
    }

    /**
     * This method optionally re-orders tasks to bring the task that launched
     * the interactive activity to the foreground. This is useful when the activity provided
     * to us does not have a taskAffinity and as a result it's possible that other apps or the home
     * screen could be in the task stack ahead of the app that launched the interactive
     * authorization UI.
     *
     * @param command The BaseCommand.
     */
    private void optionallyReorderTasks(@NonNull final ICommand<?> command) {
        final String methodName = ":optionallyReorderTasks";
        if (command instanceof InteractiveTokenCommand) {
            if (mActivity == null){
                throw new IllegalStateException("Activity cannot be null in an interactive session.");
            }

            final InteractiveTokenCommand interactiveTokenCommand = (InteractiveTokenCommand) command;
            final InteractiveTokenCommandParameters interactiveTokenCommandParameters = (InteractiveTokenCommandParameters) interactiveTokenCommand.getParameters();
            if (interactiveTokenCommandParameters.getHandleNullTaskAffinity() && !hasTaskAffinity(mActivity)) {
                //If an interactive command doesn't have a task affinity bring the
                //task that launched the command to the foreground
                //In order for this to work the app has to have requested the re-order tasks permission
                //https://developer.android.com/reference/android/Manifest.permission#REORDER_TASKS
                //if the permission has not been granted nothing will happen if you just invoke the method
                final ActivityManager activityManager = (ActivityManager) mContext.getSystemService(Context.ACTIVITY_SERVICE);
                if (activityManager != null) {
                    activityManager.moveTaskToFront(mActivity.getTaskId(), 0);
                } else {
                    Logger.warn(TAG + methodName, "ActivityManager was null; Unable to bring task for the foreground.");
                }
            }
        }
    }

    private static boolean hasTaskAffinity(@NonNull final Activity activity) {
        final String methodName = ":hasTaskAffinity";
        final PackageManager packageManager = activity.getPackageManager();
        try {
            final ComponentName componentName = activity.getComponentName();
            final ActivityInfo startActivityInfo = componentName != null ? packageManager.getActivityInfo(componentName, 0) : null;
            if (startActivityInfo == null) {
                return false;
            }
            return startActivityInfo.taskAffinity != null;
        } catch (final PackageManager.NameNotFoundException e) {
            Logger.warn(
                    TAG + methodName,
                    "Unable to get ActivityInfo for activity provided to start authorization."
            );

            //Normally all tasks have an affinity unless configured explicitly for multi-window support to not have one
            return true;
        }
    }
}
