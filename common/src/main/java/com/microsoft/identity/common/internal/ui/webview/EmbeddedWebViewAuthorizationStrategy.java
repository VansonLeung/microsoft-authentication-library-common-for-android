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
import android.net.Uri;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import com.microsoft.identity.common.BaseAccount;
import com.microsoft.identity.common.adal.internal.AuthenticationConstants;
import com.microsoft.identity.common.exception.ClientException;
import com.microsoft.identity.common.internal.logging.Logger;
import com.microsoft.identity.common.internal.providers.oauth2.AccessToken;
import com.microsoft.identity.common.internal.providers.oauth2.AuthorizationActivity;
import com.microsoft.identity.common.internal.providers.oauth2.AuthorizationErrorResponse;
import com.microsoft.identity.common.internal.providers.oauth2.AuthorizationRequest;
import com.microsoft.identity.common.internal.providers.oauth2.AuthorizationResponse;
import com.microsoft.identity.common.internal.providers.oauth2.AuthorizationResult;
import com.microsoft.identity.common.internal.providers.oauth2.AuthorizationStrategy;
import com.microsoft.identity.common.internal.providers.oauth2.OAuth2Configuration;
import com.microsoft.identity.common.internal.providers.oauth2.OAuth2Strategy;
import com.microsoft.identity.common.internal.providers.oauth2.OAuth2StrategyParameters;
import com.microsoft.identity.common.internal.providers.oauth2.RefreshToken;
import com.microsoft.identity.common.internal.providers.oauth2.TokenRequest;
import com.microsoft.identity.common.internal.providers.oauth2.TokenResponse;
import com.microsoft.identity.common.internal.providers.oauth2.TokenResult;
import com.microsoft.identity.common.internal.result.ResultFuture;
import com.microsoft.identity.common.internal.ui.AuthorizationAgent;

import java.io.UnsupportedEncodingException;
import java.util.concurrent.Future;

/**
 * Serve as a class to do the OAuth2 auth code grant flow with Android embedded web view.
 */
public class EmbeddedWebViewAuthorizationStrategy<GenericOAuth2Strategy extends OAuth2Strategy<? extends AccessToken,
        ? extends BaseAccount,
        ? extends AuthorizationRequest<?>,
        ? extends AuthorizationRequest.Builder<?>,
        ? extends AuthorizationStrategy<?,?>,
        ? extends OAuth2Configuration,
        ? extends OAuth2StrategyParameters,
        ? extends AuthorizationResponse,
        ? extends RefreshToken,
        ? extends TokenRequest,
        ? extends TokenResponse,
        ? extends TokenResult,
        ? extends AuthorizationResult<AuthorizationResponse, AuthorizationErrorResponse>>,
        GenericAuthorizationRequest extends AuthorizationRequest<?>> extends AuthorizationStrategy<GenericOAuth2Strategy, AuthorizationRequest<?>> {

    private static final String TAG = EmbeddedWebViewAuthorizationStrategy.class.getSimpleName();
    private ResultFuture<AuthorizationResult<AuthorizationResponse, AuthorizationErrorResponse>> mAuthorizationResultFuture;
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
    @SuppressWarnings("unchecked")
    public Future<AuthorizationResult<AuthorizationResponse, AuthorizationErrorResponse>> requestAuthorization(AuthorizationRequest<?> authorizationRequest, OAuth2Strategy<? extends AccessToken, ? extends BaseAccount, ? extends AuthorizationRequest<?>, ? extends AuthorizationRequest.Builder<?>, ? extends AuthorizationStrategy<?, ?>, ? extends OAuth2Configuration, ? extends OAuth2StrategyParameters, ? extends AuthorizationResponse, ? extends RefreshToken, ? extends TokenRequest, ? extends TokenResponse, ? extends TokenResult, ? extends AuthorizationResult<AuthorizationResponse, AuthorizationErrorResponse>> oAuth2Strategy) throws ClientException, UnsupportedEncodingException {
        mOAuth2Strategy = (GenericOAuth2Strategy)oAuth2Strategy;
        mAuthorizationRequest =(GenericAuthorizationRequest) authorizationRequest;
        Logger.info(TAG, "Perform the authorization request with embedded webView.");
        final Uri requestUrl = authorizationRequest.getAuthorizationRequestAsHttpRequest();
        final Intent authIntent = AuthorizationActivity.createStartIntent(
                getApplicationContext(),
                null,
                requestUrl.toString(),
                mAuthorizationRequest.getRedirectUri(),
                mAuthorizationRequest.getRequestHeaders(),
                AuthorizationAgent.WEBVIEW,
                mAuthorizationRequest.isWebViewZoomEnabled(),
                mAuthorizationRequest.isWebViewZoomControlsEnabled());

        launchIntent(authIntent);
        return mAuthorizationResultFuture;
    }

    @Override
    public void completeAuthorization(int requestCode, int resultCode, Intent data) {
        if (requestCode == AuthenticationConstants.UIRequest.BROWSER_FLOW) {
            if (mOAuth2Strategy != null && mAuthorizationResultFuture != null) {
                final AuthorizationResult<?,?> result = mOAuth2Strategy
                        .getAuthorizationResultFactory()
                        .createAuthorizationResult(
                                resultCode,
                                data,
                                mAuthorizationRequest
                        );
                @SuppressWarnings("unchecked")
                AuthorizationResult<AuthorizationResponse, AuthorizationErrorResponse> castResult = (AuthorizationResult<AuthorizationResponse, AuthorizationErrorResponse>)result;
                mAuthorizationResultFuture.setResult(castResult);
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
