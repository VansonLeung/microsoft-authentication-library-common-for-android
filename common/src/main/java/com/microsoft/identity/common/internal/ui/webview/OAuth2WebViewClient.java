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
import android.graphics.Bitmap;
import android.net.Uri;
import android.net.http.SslError;
import android.os.Build;
import android.os.Message;
import android.util.Log;
import android.view.KeyEvent;
import android.view.View;
import android.webkit.ClientCertRequest;
import android.webkit.HttpAuthHandler;
import android.webkit.RenderProcessGoneDetail;
import android.webkit.SafeBrowsingResponse;
import android.webkit.SslErrorHandler;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import androidx.annotation.VisibleForTesting;

import com.microsoft.identity.common.adal.internal.AuthenticationConstants;
import com.microsoft.identity.common.internal.ui.webview.challengehandlers.ChallengeFactory;
import com.microsoft.identity.common.java.ui.webview.authorization.IAuthorizationCompletionCallback;
import com.microsoft.identity.common.internal.ui.webview.challengehandlers.IChallengeHandler;
import com.microsoft.identity.common.internal.ui.webview.challengehandlers.NtlmChallenge;
import com.microsoft.identity.common.internal.ui.webview.challengehandlers.NtlmChallengeHandler;
import com.microsoft.identity.common.internal.util.StringUtil;
import com.microsoft.identity.common.java.exception.ClientException;
import com.microsoft.identity.common.java.providers.RawAuthorizationResult;
import com.microsoft.identity.common.logging.Logger;

import static com.microsoft.identity.common.adal.internal.AuthenticationConstants.Browser.SSL_HELP_URL;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

public abstract class OAuth2WebViewClient extends WebViewClient {
    /* constants */
    private static final String TAG = OAuth2WebViewClient.class.getSimpleName();

    private final IAuthorizationCompletionCallback mCompletionCallback;
    private final OnPageLoadedCallback mPageLoadedCallback;
    private final Activity mActivity;

    @SuppressFBWarnings(value = "MS_SHOULD_BE_FINAL", justification = "This is only exposed in testing")
    @VisibleForTesting
    public static ExpectedPage mExpectedPage = null;

    /**
     * @return context
     */
    public Activity getActivity() {
        return mActivity;
    }

    /**
     * @return handler completion callback
     */
    IAuthorizationCompletionCallback getCompletionCallback() {
        return mCompletionCallback;
    }

    /**
     * Constructor for the OAuth2 basic web view client.
     *
     * @param activity           app Context
     * @param completionCallback Challenge completion callback
     * @param pageLoadedCallback callback to be triggered on page load. For UI purposes.
     */
    OAuth2WebViewClient(@NonNull final Activity activity,
                        @NonNull final IAuthorizationCompletionCallback completionCallback,
                        @NonNull final OnPageLoadedCallback pageLoadedCallback) {
        //the validation of redirect url and authorization request should be in upper level before launching the webview.
        mActivity = activity;
        mCompletionCallback = completionCallback;
        mPageLoadedCallback = pageLoadedCallback;
    }

    @Override
    public void onReceivedHttpAuthRequest(WebView view, final HttpAuthHandler handler,
                                          String host, String realm) {
        // Create a dialog to ask for credentials and post it to the handler.
        Logger.info(TAG, "Receive the http auth request. Start the dialog to ask for creds. ");
        Logger.infoPII(TAG, "Host:" + host);

        //TODO TelemetryEvent.setNTLM(true); after the Telemetry is finished in common.
        // Use ChallengeFactory to produce a NtlmChallenge
        final NtlmChallenge ntlmChallenge = ChallengeFactory.getNtlmChallenge(view, handler, host, realm);

        // Init the NtlmChallengeHandler
        final IChallengeHandler<NtlmChallenge, Void> challengeHandler = new NtlmChallengeHandler(mActivity, mCompletionCallback);

        //Process the challenge through the NtlmChallengeHandler created
        challengeHandler.processChallenge(ntlmChallenge);
    }

    @Override
    public void onReceivedHttpError(WebView view, WebResourceRequest request, WebResourceResponse errorResponse) {
        Log.d(TAG, "onReceivedHttpError");
        super.onReceivedHttpError(view, request, errorResponse);
    }

    @Override
    public void onFormResubmission(WebView view, Message dontResend, Message resend) {
        Log.d(TAG, "onFormResubmission");
        super.onFormResubmission(view, dontResend, resend);
    }

    @Override
    public void onPageCommitVisible(WebView view, String url) {
        Log.d(TAG, "onPageCommitVisible");
        super.onPageCommitVisible(view, url);
    }

    @Override
    public void onReceivedClientCertRequest(WebView view, ClientCertRequest request) {
        Log.d(TAG, "onReceivedClientCertRequest");
        super.onReceivedClientCertRequest(view, request);
    }

    @Override
    public void onReceivedLoginRequest(WebView view, String realm, @Nullable String account, String args) {
        Log.d(TAG, "onReceivedLoginRequest");
        super.onReceivedLoginRequest(view, realm, account, args);
    }

    @Override
    public void onSafeBrowsingHit(WebView view, WebResourceRequest request, int threatType, SafeBrowsingResponse callback) {
        Log.d(TAG, "onSafeBrowsingHit");
        super.onSafeBrowsingHit(view, request, threatType, callback);
    }

    @Override
    public void onScaleChanged(WebView view, float oldScale, float newScale) {
        Log.d(TAG, "onScaleChanged");
        super.onScaleChanged(view, oldScale, newScale);
    }

    @Override
    public void onUnhandledKeyEvent(WebView view, KeyEvent event) {
        Log.d(TAG, "onUnhandledKeyEvent");
        super.onUnhandledKeyEvent(view, event);
    }

    @Override
    @SuppressWarnings("deprecation")
    public void onReceivedError(final WebView view,
                                final int errorCode,
                                final String description,
                                final String failingUrl) {
        sendErrorToCallback(view, errorCode, description);
    }

    @Override
    public void onLoadResource(WebView view, String url) {
        super.onLoadResource(view, url);
        Log.d(TAG, "onLoadResource");
    }

    @Override
    public void onTooManyRedirects(WebView view, Message cancelMsg, Message continueMsg) {
        super.onTooManyRedirects(view, cancelMsg, continueMsg);
        Log.d(TAG, "onTooMayRedirects");
    }

    @Override
    public boolean onRenderProcessGone(WebView view, RenderProcessGoneDetail detail) {
        Log.d(TAG, "onRenderProcessGone");
        return super.onRenderProcessGone(view, detail);
    }

    /**
     * API 23+ overload of {@link #onReceivedError(WebView, int, String, String)} - unlike the pre-23
     * impl, this overload will trigger pageload errors for subframes of the page. As these may not
     * necessarily affect the sign-in experience (such as failed scripts in an iframe), we are going
     * to ignore errors for the non-main-frame such that the pre-API 23 behavior is preserved.
     * <p>
     * More info:
     * https://stackoverflow.com/questions/44068123/how-to-detect-errors-only-from-the-main-page-in-new-onreceivederror-from-webview
     * https://developer.android.com/reference/android/webkit/WebViewClient#onReceivedError(android.webkit.WebView,%20android.webkit.WebResourceRequest,%20android.webkit.WebResourceError)
     *
     * @param view    The WebView which triggered the error.
     * @param request The request which failed within the page.
     * @param error   The error yielded by the failing request.
     * @see #onReceivedError(WebView, int, String, String)
     */
    @Override
    @RequiresApi(api = Build.VERSION_CODES.M)
    public void onReceivedError(@NonNull final WebView view,
                                @NonNull final WebResourceRequest request,
                                @NonNull final WebResourceError error) {
        final String methodName = "onReceivedError (23)";
        final boolean isForMainFrame = request.isForMainFrame();

        Logger.warn(TAG + methodName, "WebResourceError - isForMainFrame? " + isForMainFrame);
        Logger.warnPII(TAG + methodName, "Failing url: " + request.getUrl());

        if (request.isForMainFrame()) {
            sendErrorToCallback(view, error.getErrorCode(), error.getDescription().toString());
        }
    }

    private void sendErrorToCallback(@NonNull final WebView view,
                                     final int errorCode,
                                     @NonNull final String description) {
        view.stopLoading();

        // Send the result back to the calling activity
        mCompletionCallback.onChallengeResponseReceived(
                RawAuthorizationResult.fromException(
                        new ClientException("Code:" + errorCode, description)));
    }

    @Override
    public void onReceivedSslError(final WebView view,
                                   final SslErrorHandler handler,
                                   final SslError error) {
        // Developer does not have option to control this for now
        super.onReceivedSslError(view, handler, error);
        handler.cancel();

        final String errMsg = "Received SSL Error during request. For more info see: " + SSL_HELP_URL;

        Logger.error(TAG + ":onReceivedSslError", errMsg, null);

        // Send the result back to the calling activity
        mCompletionCallback.onChallengeResponseReceived(
                RawAuthorizationResult.fromException(
                        new ClientException("Code:" + ERROR_FAILED_SSL_HANDSHAKE, error.toString())));
    }

    @Override
    public void onPageFinished(final WebView view,
                               final String url) {
        Log.d(TAG, "onPageFinished");
        super.onPageFinished(view, url);
        mPageLoadedCallback.onPageLoaded(url);

        //Supports UI Automation... informing that the webview resource is now idle
        if (mExpectedPage != null && url.startsWith(mExpectedPage.mExpectedPageUrlStartsWith)) {
            mExpectedPage.mCallback.onPageLoaded(url);
        }

        // Once web view is fully loaded,set to visible
        view.setVisibility(View.VISIBLE);
    }

    @Override
    public void onPageStarted(final WebView view,
                              final String url,
                              final Bitmap favicon) {
//        checkStartUrl(url);
        Logger.info(TAG, "WebView starts loading.");
        super.onPageStarted(view, url, favicon);
    }

    private void checkStartUrl(final String url) {
        if (StringUtil.isEmpty(url)) {
            Logger.info(TAG, "onPageStarted: Null url for page to load.");
            return;
        }

        final Uri uri = Uri.parse(url);
        if (uri.isOpaque()) {
            Logger.info(TAG, "onPageStarted: Non-hierarchical loading uri.");
            Logger.infoPII(TAG, "start url: " + url);
        } else if (StringUtil.isEmpty(uri.getQueryParameter(AuthenticationConstants.OAuth2.CODE))) {
            Logger.info(TAG, "onPageStarted: URI has no auth code ('"
                    + AuthenticationConstants.OAuth2.CODE + "') query parameter.");
            Logger.infoPII(TAG, "Scheme:" + uri.getScheme() + " Host: " + uri.getHost()
                    + " Path: " + uri.getPath());
        } else {
            Logger.info(TAG, "Auth code is returned for the loading url.");
            Logger.infoPII(TAG, "Scheme:" + uri.getScheme() + " Host: " + uri.getHost()
                    + " Path: " + uri.getPath());
        }
    }
}
