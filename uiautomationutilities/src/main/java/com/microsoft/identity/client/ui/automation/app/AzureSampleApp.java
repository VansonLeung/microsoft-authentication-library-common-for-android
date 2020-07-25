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
package com.microsoft.identity.client.ui.automation.app;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.test.uiautomator.UiObject;
import androidx.test.uiautomator.UiObjectNotFoundException;

import com.microsoft.identity.client.ui.automation.browser.IBrowser;
import com.microsoft.identity.client.ui.automation.installer.LocalApkInstaller;
import com.microsoft.identity.client.ui.automation.interaction.microsoftsts.MicrosoftStsPromptHandler;
import com.microsoft.identity.client.ui.automation.interaction.microsoftsts.MicrosoftStsPromptHandlerParameters;
import com.microsoft.identity.client.ui.automation.utils.UiAutomatorUtils;

import org.junit.Assert;

/**
 * This class models the Azure Sample App for MSAL Android.
 * This refers to app stored in Azure-Samples/ms-identity-android-java repository.
 * See this: https://github.com/Azure-Samples/ms-identity-android-java
 */
public class AzureSampleApp extends App {

    private static final String AZURE_SAMPLE_PACKAGE_NAME = "com.azuresamples.msalandroidapp";
    private static final String AZURE_SAMPLE_APP_NAME = "Azure Sample";
    public final static String AZURE_SAMPLE_APK = "AzureSample.apk";

    public AzureSampleApp() {
        super(AZURE_SAMPLE_PACKAGE_NAME, AZURE_SAMPLE_APP_NAME, new LocalApkInstaller());
        localApkFileName = AZURE_SAMPLE_APK;
    }

    @Override
    public void handleFirstRun() {
        // nothing required
    }

    /**
     * Sign in into the Azure Sample App. Please note that this method performs sign in into the
     * Single Account Mode Fragment in the Sample App.
     *
     * @param username                    the username of the account to sign in
     * @param password                    the password of the account to sign in
     * @param browser                     the browser that is expected to be used during sign in flow
     * @param shouldHandleBrowserFirstRun whether this is the first time the browser being run
     * @param promptHandlerParameters     the prompt handler parameters indicating how to handle prompt
     */
    public void signIn(@NonNull final String username,
                       @NonNull final String password,
                       @Nullable final IBrowser browser,
                       final boolean shouldHandleBrowserFirstRun,
                       @NonNull final MicrosoftStsPromptHandlerParameters promptHandlerParameters) {
        // Click Sign In in Single Account Fragment
        UiAutomatorUtils.handleButtonClick("com.azuresamples.msalandroidapp:id/btn_signIn");

        if (promptHandlerParameters.getBroker() == null && browser != null && shouldHandleBrowserFirstRun) {
            // handle browser first run as applicable
            ((IApp) browser).handleFirstRun();
        }

        // handle prompt in AAD login page
        MicrosoftStsPromptHandler microsoftStsPromptHandler =
                new MicrosoftStsPromptHandler(promptHandlerParameters);

        microsoftStsPromptHandler.handlePrompt(username, password);
    }

    /**
     * Sing out of the Azure Sample App. Please note that this method performs sign out of the
     * Single Account mode fragment in the Azure Sample App.
     */
    public void signOut() {
        UiAutomatorUtils.handleButtonClick("com.azuresamples.msalandroidapp:id/btn_removeAccount");
    }

    /**
     * Makes sure that the provided username is already signed into the Azure Sample App
     *
     * @param username the username of the account for which to confirm sign in
     */
    public void confirmSignedIn(@NonNull final String username) {
        final UiObject signedInUser = UiAutomatorUtils.obtainUiObjectWithResourceId("com.azuresamples.msalandroidapp:id/current_user");
        try {
            Assert.assertEquals(signedInUser.getText(), username);
        } catch (UiObjectNotFoundException e) {
            Assert.fail(e.getMessage());
        }
    }
}
