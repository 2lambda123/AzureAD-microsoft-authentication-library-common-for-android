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

package com.microsoft.identity.common.internal.util;

import android.app.admin.DevicePolicyManager;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.UserManager;

import androidx.annotation.NonNull;

import com.microsoft.identity.common.adal.internal.AuthenticationConstants;
import com.microsoft.identity.common.internal.logging.Logger;

public final class AccountManagerUtil {
    private static final String TAG = AccountManagerUtil.class.getSimpleName();

    private static final String MANIFEST_PERMISSION_MANAGE_ACCOUNTS = "android.permission.MANAGE_ACCOUNTS";

    private AccountManagerUtil() {}

    /**
     * To verify if the caller can use to AccountManager to use broker.
     */
    public static boolean canUseAccountManagerOperation(final Context context) {
        final String methodName = "canUseAccountManagerOperation:";

        if (android.os.Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            // Check user policy
            final UserManager userManager = (UserManager) context.getSystemService(Context.USER_SERVICE);
            if (userManager.hasUserRestriction(UserManager.DISALLOW_MODIFY_ACCOUNTS)) {
                Logger.verbose(TAG + methodName, "UserManager.DISALLOW_MODIFY_ACCOUNTS is enabled for this user.");
                return false;
            }

            // Check if our account type is disabled.
            final DevicePolicyManager devicePolicyManager =
                    (DevicePolicyManager) context.getSystemService(Context.DEVICE_POLICY_SERVICE);
            for (final String accountType : devicePolicyManager.getAccountTypesWithManagementDisabled()){
                if (AuthenticationConstants.Broker.BROKER_ACCOUNT_TYPE.equalsIgnoreCase(accountType)){
                    Logger.verbose(TAG + methodName, "Broker account type is disabled by MDM.");
                    return false;
                }
            }

            // Before Android 6.0, the MANAGE_ACCOUNTS permission is required in the app's manifest xml file.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                return true;
            } else {
                return isPermissionGranted(context, MANIFEST_PERMISSION_MANAGE_ACCOUNTS);
            }
        }

        // Unable to determine - treat this as false.
        // If the restriction exists and we make an accountManager call, then the OS will pop a dialog up.
        Logger.verbose(TAG + methodName,
                "Cannot verify. Skipping AccountManager operation.");
        return false;
    }

    private static boolean isPermissionGranted(@NonNull final Context context,
                                               @NonNull final String permissionName) {
        final String methodName = ":isPermissionGranted";
        final PackageManager pm = context.getPackageManager();
        final boolean isGranted = pm.checkPermission(permissionName, context.getPackageName())
                == PackageManager.PERMISSION_GRANTED;
        Logger.verbose(TAG + methodName, "is " + permissionName + " granted? [" + isGranted + "]");
        return isGranted;
    }
}
