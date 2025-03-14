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
package com.microsoft.identity.common.internal.ui.webview;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import com.microsoft.identity.common.internal.providers.oauth2.AndroidAuthorizationStrategy;
import com.microsoft.identity.common.internal.providers.oauth2.AuthorizationActivityFactory;
import com.microsoft.identity.common.java.WarningType;
import com.microsoft.identity.common.java.exception.ClientException;
import com.microsoft.identity.common.java.providers.RawAuthorizationResult;
import com.microsoft.identity.common.java.providers.oauth2.AuthorizationRequest;
import com.microsoft.identity.common.java.providers.oauth2.OAuth2Strategy;
import com.microsoft.identity.common.java.providers.oauth2.AuthorizationResult;
import com.microsoft.identity.common.java.util.ResultFuture;
import com.microsoft.identity.common.java.ui.AuthorizationAgent;
import com.microsoft.identity.common.logging.Logger;

import java.net.URI;
import java.util.concurrent.Future;

import static com.microsoft.identity.common.java.AuthenticationConstants.UIRequest.BROWSER_FLOW;

/**
 * Serve as a class to do the OAuth2 auth code grant flow with Android embedded web view.
 */
// Suppressing rawtype warnings due to the generic types OAuth2Strategy, AuthorizationRequest and AuthorizationResult
@SuppressWarnings(WarningType.rawtype_warning)
public class EmbeddedWebViewAuthorizationStrategy<GenericOAuth2Strategy extends OAuth2Strategy,
        GenericAuthorizationRequest extends AuthorizationRequest> extends AndroidAuthorizationStrategy<GenericOAuth2Strategy, GenericAuthorizationRequest> {

    private static final String TAG = EmbeddedWebViewAuthorizationStrategy.class.getSimpleName();
    private ResultFuture<AuthorizationResult> mAuthorizationResultFuture;
    private GenericOAuth2Strategy mOAuth2Strategy; //NOPMD
    private GenericAuthorizationRequest mAuthorizationRequest; //NOPMD

    /**
     * Constructor of EmbeddedWebViewAuthorizationStrategy.
     *
     * @param activity The app activity which invoke the interactive auth request.
     */
    public EmbeddedWebViewAuthorizationStrategy(@NonNull Context applicationContext,
                                                @NonNull Activity activity,
                                                @Nullable Fragment fragment) {
        super(applicationContext, activity, fragment);
    }

    /**
     * RequestAuthorization could not return the authorization result.
     * The activity result is set in Authorization.setResult() and passed to the onActivityResult() of the calling activity.
     */
    @Override
    public Future<AuthorizationResult> requestAuthorization(GenericAuthorizationRequest authorizationRequest,
                                                            GenericOAuth2Strategy oAuth2Strategy) throws ClientException {
        mAuthorizationResultFuture = new ResultFuture<>();
        mOAuth2Strategy = oAuth2Strategy;
        mAuthorizationRequest = authorizationRequest;
        Logger.info(TAG, "Perform the authorization request with embedded webView.");
        final URI requestUrl = authorizationRequest.getAuthorizationRequestAsHttpRequest();
        final Intent authIntent = buildAuthorizationActivityStartIntent(requestUrl);

        launchIntent(authIntent);
        return mAuthorizationResultFuture;
    }

    // Suppressing unchecked warnings during casting to HashMap<String,String> due to no generic type with mAuthorizationRequest
    @SuppressWarnings(WarningType.unchecked_warning)
    private Intent buildAuthorizationActivityStartIntent(URI requestUrl) {
        return AuthorizationActivityFactory.getAuthorizationActivityIntent(
                    getApplicationContext(),
                    null,
                    requestUrl.toString(),
                    mAuthorizationRequest.getRedirectUri(),
                    mAuthorizationRequest.getRequestHeaders(),
                    AuthorizationAgent.WEBVIEW,
                    mAuthorizationRequest.isWebViewZoomEnabled(),
                    mAuthorizationRequest.isWebViewZoomControlsEnabled());
    }

    @Override
    public void completeAuthorization(int requestCode, @NonNull final RawAuthorizationResult data) {
        if (requestCode == BROWSER_FLOW) {
            if (mOAuth2Strategy != null && mAuthorizationResultFuture != null) {

                //Suppressing unchecked warnings due to method createAuthorizationResult being a member of the raw type AuthorizationResultFactory
                @SuppressWarnings(WarningType.unchecked_warning) final AuthorizationResult result = mOAuth2Strategy
                        .getAuthorizationResultFactory()
                        .createAuthorizationResult(
                                data,
                                mAuthorizationRequest
                        );
                mAuthorizationResultFuture.setResult(result);
            } else {
                Logger.warn(TAG, "SDK Cancel triggering before request is sent out. " +
                        "Potentially due to an stale activity state, " +
                        "oAuth2Strategy null ? [" + (mOAuth2Strategy == null) + "]" +
                        "mAuthorizationResultFuture ? [" + (mAuthorizationResultFuture == null) + "]"
                );
            }
        } else {
            Logger.warnPII(TAG, "Unknown request code " + requestCode);
        }
    }
}
