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
package com.microsoft.identity.common.java.util;

import com.microsoft.identity.common.java.commands.ICommand;
import com.microsoft.identity.common.java.eststelemetry.LastRequestTelemetryCache;
import com.microsoft.identity.common.java.exception.ClientException;
import com.microsoft.identity.common.java.exception.ErrorStrings;
import com.microsoft.identity.common.java.ui.BrowserDescriptor;

import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

public interface IPlatformUtil {

    /**
     * Return a list of BrowserDescriptors that are considered safe for the given platform.
     */
    List<BrowserDescriptor> getBrowserSafeListForBroker();

    /**
     * Gets version of the installed Company Portal app.
     * Returns null if the app is not installed, the value cannot be retrieved, or this operation is not supported.
     */
    @Nullable
    String getInstalledCompanyPortalVersion();

    /**
     * Check if the network is available. If the network is unavailable, {@link ClientException}
     * will throw with error code {@link ErrorStrings#NO_NETWORK_CONNECTION_POWER_OPTIMIZATION}
     * when connection is not available to refresh token because power optimization is enabled, or
     * throw with error code {@link ErrorStrings#DEVICE_NETWORK_NOT_AVAILABLE} otherwise.
     *
     * @param performPowerOptimizationCheck True, if power optimization checks should be performed.
     *                                      False otherwise.
     * @throws ClientException throw network exception
     */
    void throwIfNetworkNotAvailable(final boolean performPowerOptimizationCheck) throws ClientException;

    /**
     * Clear all cookies from embedded webview.
     * This might be a blocking call, so should not be called on UI thread.
     */
    void removeCookiesFromWebView();

    /**
     * Validate that the app owns the redirect URI.
     * Returns true if nothing goes wrong.
     */
    boolean isValidCallingApp(@NonNull final String redirectUri, @NonNull final String packageName);

    /**
     * Retrieve the Intune MAM enrollment id for the given user and package from
     * the Intune Company Portal, if available.
     *
     * @param userId      object id of the user for whom a token is being acquired.
     * @param packageName name of the package requesting the token.
     * @return the enrollment id, or null if enrollment id can't be retrieved.
     */
    @Nullable
    String getEnrollmentId(@NonNull final String userId, @NonNull final String packageName);

    /**
     * An operation to be triggered when result of a {@link ICommand} is returned.
     */
    void onReturnCommandResult(@NonNull final ICommand<?> command);

    /**
     * @return a view of the elapsed time in nanoseconds.  This is *only useful* as a measure of
     * time differences to other points acquired from this precise method in the same thread.
     */
    long getNanosecondTime();

    /**
     * Posts a runnable for returning the command execution result.
     */
    void postCommandResult(@NonNull final Runnable runnable);
}
