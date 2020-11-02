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
package com.microsoft.identity.common.internal.controllers;

import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.text.TextUtils;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.microsoft.identity.common.WarningType;
import com.microsoft.identity.common.adal.internal.AuthenticationConstants;
import com.microsoft.identity.common.exception.BaseException;
import com.microsoft.identity.common.exception.ClientException;
import com.microsoft.identity.common.exception.ErrorStrings;
import com.microsoft.identity.common.exception.ServiceException;
import com.microsoft.identity.common.internal.authorities.AzureActiveDirectoryAudience;
import com.microsoft.identity.common.internal.broker.BrokerActivity;
import com.microsoft.identity.common.internal.broker.BrokerResult;
import com.microsoft.identity.common.internal.broker.BrokerResultFuture;
import com.microsoft.identity.common.internal.broker.BrokerValidator;
import com.microsoft.identity.common.internal.broker.MicrosoftAuthClient;
import com.microsoft.identity.common.internal.broker.ipc.AccountManagerAddAccountStrategy;
import com.microsoft.identity.common.internal.broker.ipc.BoundServiceStrategy;
import com.microsoft.identity.common.internal.broker.ipc.BrokerOperationBundle;
import com.microsoft.identity.common.internal.broker.ipc.ContentProviderStrategy;
import com.microsoft.identity.common.internal.broker.ipc.IIpcStrategy;
import com.microsoft.identity.common.internal.cache.ICacheRecord;
import com.microsoft.identity.common.internal.cache.MsalOAuth2TokenCache;
import com.microsoft.identity.common.internal.commands.parameters.CommandParameters;
import com.microsoft.identity.common.internal.commands.parameters.DeviceCodeFlowCommandParameters;
import com.microsoft.identity.common.internal.commands.parameters.InteractiveTokenCommandParameters;
import com.microsoft.identity.common.internal.commands.parameters.RemoveAccountCommandParameters;
import com.microsoft.identity.common.internal.commands.parameters.SilentTokenCommandParameters;
import com.microsoft.identity.common.internal.logging.Logger;
import com.microsoft.identity.common.internal.providers.microsoft.MicrosoftRefreshToken;
import com.microsoft.identity.common.internal.providers.microsoft.azureactivedirectory.ClientInfo;
import com.microsoft.identity.common.internal.providers.microsoft.microsoftsts.MicrosoftStsAccount;
import com.microsoft.identity.common.internal.providers.oauth2.AuthorizationResult;
import com.microsoft.identity.common.internal.providers.oauth2.IDToken;
import com.microsoft.identity.common.internal.request.MsalBrokerRequestAdapter;
import com.microsoft.identity.common.internal.result.AcquireTokenResult;
import com.microsoft.identity.common.internal.result.MsalBrokerResultAdapter;
import com.microsoft.identity.common.internal.telemetry.Telemetry;
import com.microsoft.identity.common.internal.telemetry.TelemetryEventStrings;
import com.microsoft.identity.common.internal.telemetry.events.ApiEndEvent;
import com.microsoft.identity.common.internal.telemetry.events.ApiStartEvent;
import com.microsoft.identity.common.internal.ui.browser.Browser;
import com.microsoft.identity.common.internal.ui.browser.BrowserSelector;
import com.microsoft.identity.common.internal.util.AccountManagerUtil;
import com.microsoft.identity.common.internal.util.StringUtil;

import java.util.ArrayList;
import java.util.List;

import lombok.EqualsAndHashCode;

import static com.microsoft.identity.common.internal.broker.ipc.BrokerOperationBundle.Operation.MSAL_ACQUIRE_TOKEN_SILENT;
import static com.microsoft.identity.common.internal.broker.ipc.BrokerOperationBundle.Operation.MSAL_GET_ACCOUNTS;
import static com.microsoft.identity.common.internal.broker.ipc.BrokerOperationBundle.Operation.MSAL_GET_CURRENT_ACCOUNT_IN_SHARED_DEVICE;
import static com.microsoft.identity.common.internal.broker.ipc.BrokerOperationBundle.Operation.MSAL_GET_DEVICE_MODE;
import static com.microsoft.identity.common.internal.broker.ipc.BrokerOperationBundle.Operation.MSAL_GET_INTENT_FOR_INTERACTIVE_REQUEST;
import static com.microsoft.identity.common.internal.broker.ipc.BrokerOperationBundle.Operation.MSAL_REMOVE_ACCOUNT;
import static com.microsoft.identity.common.internal.broker.ipc.BrokerOperationBundle.Operation.MSAL_SIGN_OUT_FROM_SHARED_DEVICE;
import static com.microsoft.identity.common.internal.controllers.BrokerOperationExecutor.BrokerOperation;

/**
 * The implementation of MSAL Controller for Broker.
 */
@EqualsAndHashCode(callSuper = true, onlyExplicitlyIncluded = true)
public class BrokerMsalController extends BaseController {

    private static final String TAG = BrokerMsalController.class.getSimpleName();

    protected final MsalBrokerRequestAdapter mRequestAdapter = new MsalBrokerRequestAdapter();
    protected final MsalBrokerResultAdapter mResultAdapter = new MsalBrokerResultAdapter();

    private BrokerResultFuture mBrokerResultFuture;
    private final Context mApplicationContext;
    private final String mActiveBrokerPackageName;
    private final BrokerOperationExecutor mBrokerOperationExecutor;

    public BrokerMsalController(final Context applicationContext) {
        mApplicationContext = applicationContext;
        mActiveBrokerPackageName = new BrokerValidator(mApplicationContext).getCurrentActiveBrokerPackageName();
        if (TextUtils.isEmpty(mActiveBrokerPackageName)) {
            throw new IllegalStateException("Active Broker not found. This class should not be initialized.");
        }

        mBrokerOperationExecutor = new BrokerOperationExecutor(getIpcStrategies(mApplicationContext, mActiveBrokerPackageName));
    }

    /**
     * Gets a list of communication strategies.
     * Order of objects in the list will reflects the order of strategies that will be used.
     */
    private static @NonNull List<IIpcStrategy> getIpcStrategies(final Context applicationContext,
                                                                final String activeBrokerPackageName) {
        final List<IIpcStrategy> strategies = new ArrayList<>();
        final StringBuilder sb = new StringBuilder(100);
        sb.append("Broker Strategies added : ");

        final ContentProviderStrategy contentProviderStrategy = new ContentProviderStrategy(applicationContext);
        if (contentProviderStrategy.isBrokerContentProviderAvailable(activeBrokerPackageName)) {
            sb.append("ContentProviderStrategy, ");
            strategies.add(contentProviderStrategy);
        }

        final MicrosoftAuthClient client = new MicrosoftAuthClient(applicationContext);
        if (client.isBoundServiceSupported(activeBrokerPackageName)) {
            sb.append("BoundServiceStrategy, ");
            strategies.add(new BoundServiceStrategy<>(client));
        }

        if (AccountManagerUtil.canUseAccountManagerOperation(applicationContext)) {
            sb.append("AccountManagerStrategy.");
            strategies.add(new AccountManagerAddAccountStrategy(applicationContext));
        }

        Logger.info(TAG, sb.toString());

        return strategies;
    }

    /**
     * MSAL-Broker handshake operation.
     *
     * @param strategy   an {@link IIpcStrategy}
     * @param parameters a {@link CommandParameters}
     * @return a protocol version negotiated by MSAL and Broker.
     */
    private @NonNull String hello(@NonNull IIpcStrategy strategy,
                                  @NonNull final CommandParameters parameters) throws BaseException {
        final BrokerOperationBundle helloBundle = new BrokerOperationBundle(
                BrokerOperationBundle.Operation.MSAL_HELLO,
                mActiveBrokerPackageName,
                mRequestAdapter.getRequestBundleForHello(parameters));

        return mResultAdapter.verifyHelloFromResultBundle(
                strategy.communicateToBroker(helloBundle)
        );
    }

    /**
     * Performs interactive acquire token with Broker.
     *
     * @param parameters a {@link InteractiveTokenCommandParameters}
     * @return an {@link AcquireTokenResult}.
     */
    @Override
    public AcquireTokenResult acquireToken(InteractiveTokenCommandParameters parameters) throws BaseException, InterruptedException {
        Telemetry.emit(
                new ApiStartEvent()
                        .putProperties(parameters)
                        .putApiId(TelemetryEventStrings.Api.BROKER_ACQUIRE_TOKEN_INTERACTIVE)
        );

        //Create BrokerResultFuture to block on response from the broker... response will be return as an activity result
        //BrokerActivity will receive the result and ask the API dispatcher to complete the request
        //In completeAcquireToken below we will set the result on the future and unblock the flow.
        mBrokerResultFuture = new BrokerResultFuture();

        //Get the broker interactive parameters intent
        final Intent interactiveRequestIntent = getBrokerAuthorizationIntent(parameters);

        //Pass this intent to the BrokerActivity which will be used to start this activity
        final Intent brokerActivityIntent = new Intent(parameters.getAndroidApplicationContext(), BrokerActivity.class);
        brokerActivityIntent.putExtra(BrokerActivity.BROKER_INTENT, interactiveRequestIntent);

        mBrokerResultFuture = new BrokerResultFuture();

        //Start the BrokerActivity
        parameters.getActivity().startActivity(brokerActivityIntent);

        //Wait to be notified of the result being returned... we could add a timeout here if we want to
        final Bundle resultBundle = mBrokerResultFuture.get();

        // For MSA Accounts Broker doesn't save the accounts, instead it just passes the result along,
        // MSAL needs to save this account locally for future token calls.
        // parameters.getOAuth2TokenCache() will be non-null only in case of MSAL native
        // If the request is from MSALCPP , OAuth2TokenCache will be null.
        if (parameters.getOAuth2TokenCache() != null) {
            saveMsaAccountToCache(resultBundle, (MsalOAuth2TokenCache) parameters.getOAuth2TokenCache());
        }

        final AcquireTokenResult result;
        try {
            result = new MsalBrokerResultAdapter().getAcquireTokenResultFromResultBundle(resultBundle);
        } catch (BaseException e) {
            Telemetry.emit(
                    new ApiEndEvent()
                            .putException(e)
                            .putApiId(TelemetryEventStrings.Api.BROKER_ACQUIRE_TOKEN_INTERACTIVE)
            );
            throw e;
        }

        Telemetry.emit(
                new ApiEndEvent()
                        .putResult(result)
                        .putApiId(TelemetryEventStrings.Api.BROKER_ACQUIRE_TOKEN_INTERACTIVE)
        );

        return result;
    }

    /**
     * Get the response from the Broker captured by BrokerActivity.
     * BrokerActivity will pass along the response to the broker controller
     * The Broker controller will map th response into the broker result
     * And signal the future with the broker result to unblock the request.
     */
    @Override
    public void completeAcquireToken(int requestCode, int resultCode, Intent data) {
        Telemetry.emit(
                new ApiStartEvent()
                        .putApiId(TelemetryEventStrings.Api.BROKER_COMPLETE_ACQUIRE_TOKEN_INTERACTIVE)
                        .put(TelemetryEventStrings.Key.RESULT_CODE, String.valueOf(resultCode))
                        .put(TelemetryEventStrings.Key.REQUEST_CODE, String.valueOf(requestCode))
        );

        mBrokerResultFuture.setResultBundle(data.getExtras());

        Telemetry.emit(
                new ApiEndEvent()
                        .putApiId(TelemetryEventStrings.Api.BROKER_COMPLETE_ACQUIRE_TOKEN_INTERACTIVE)
        );
    }

    /**
     * Get the intent for the broker interactive request
     *
     * @param parameters a {@link InteractiveTokenCommandParameters}
     * @return an {@link Intent} for initiating Broker interactive activity.
     */
    private @NonNull Intent getBrokerAuthorizationIntent(@NonNull final InteractiveTokenCommandParameters parameters) throws BaseException {
        return mBrokerOperationExecutor.execute(parameters,
                new BrokerOperation<Intent>() {
                    private String negotiatedBrokerProtocolVersion;

                    @Override
                    public void performPrerequisites(@NonNull final IIpcStrategy strategy) throws BaseException {
                        negotiatedBrokerProtocolVersion = hello(strategy, parameters);
                    }

                    @Override
                    public @NonNull BrokerOperationBundle getBundle() {
                        return new BrokerOperationBundle(
                                MSAL_GET_INTENT_FOR_INTERACTIVE_REQUEST,
                                mActiveBrokerPackageName,
                                null);
                    }

                    @Override
                    public @NonNull Intent extractResultBundle(@Nullable final Bundle resultBundle) throws BaseException {
                        if (resultBundle == null) {
                            throw mResultAdapter.getExceptionForEmptyResultBundle();
                        }

                        final Intent intent = mResultAdapter.getIntentForInteractiveRequestFromResultBundle(resultBundle);
                        intent.putExtras(
                                mRequestAdapter.getRequestBundleForAcquireTokenInteractive(parameters, negotiatedBrokerProtocolVersion)
                        );
                        return intent;
                    }

                    @Override
                    public @NonNull String getMethodName() {
                        return ":getBrokerAuthorizationIntent";
                    }

                    @Override
                    public @Nullable String getTelemetryApiId() {
                        return null;
                    }

                    @Override
                    public void putValueInSuccessEvent(ApiEndEvent event, Intent result) {
                    }
                });
    }

    /**
     * Performs acquire token silent with Broker.
     *
     * @param parameters a {@link SilentTokenCommandParameters}
     * @return an {@link AcquireTokenResult}.
     */
    @Override
    public @NonNull AcquireTokenResult acquireTokenSilent(@NonNull final SilentTokenCommandParameters parameters) throws BaseException {
        return mBrokerOperationExecutor.execute(parameters,
                new BrokerOperation<AcquireTokenResult>() {
                    private String negotiatedBrokerProtocolVersion;

                    @Override
                    public void performPrerequisites(@NonNull final IIpcStrategy strategy) throws BaseException {
                        negotiatedBrokerProtocolVersion = hello(strategy, parameters);
                    }

                    @Override
                    public @NonNull BrokerOperationBundle getBundle() {
                        return new BrokerOperationBundle(MSAL_ACQUIRE_TOKEN_SILENT,
                                mActiveBrokerPackageName,
                                mRequestAdapter.getRequestBundleForAcquireTokenSilent(
                                        parameters,
                                        negotiatedBrokerProtocolVersion
                                ));
                    }

                    @Override
                    public @NonNull AcquireTokenResult extractResultBundle(@Nullable final Bundle resultBundle) throws BaseException {
                        if (resultBundle == null) {
                            throw mResultAdapter.getExceptionForEmptyResultBundle();
                        }
                        return mResultAdapter.getAcquireTokenResultFromResultBundle(resultBundle);
                    }

                    @Override
                    public @NonNull String getMethodName() {
                        return ":acquireTokenSilent";
                    }

                    @Override
                    public @NonNull String getTelemetryApiId() {
                        return TelemetryEventStrings.Api.BROKER_ACQUIRE_TOKEN_SILENT;
                    }

                    @Override
                    public void putValueInSuccessEvent(ApiEndEvent event, AcquireTokenResult result) {
                        event.putResult(result);
                    }
                });
    }

    /**
     * Returns account(s) that has previously been used to acquire token with broker through the calling app.
     * This only works when getBrokerAccountMode() is BROKER_ACCOUNT_MODE_MULTIPLE_ACCOUNT.
     *
     * @param parameters a {@link CommandParameters}
     * @return a list of {@link ICacheRecord}.
     */
    @Override
    public @NonNull List<ICacheRecord> getAccounts(@NonNull final CommandParameters parameters) throws BaseException {
        return mBrokerOperationExecutor.execute(parameters,
                new BrokerOperation<List<ICacheRecord>>() {
                    private String negotiatedBrokerProtocolVersion;

                    @Override
                    public void performPrerequisites(@NonNull final IIpcStrategy strategy) throws BaseException {
                        negotiatedBrokerProtocolVersion = hello(strategy, parameters);
                    }

                    @Override
                    public @NonNull BrokerOperationBundle getBundle() {
                        return new BrokerOperationBundle(
                                MSAL_GET_ACCOUNTS,
                                mActiveBrokerPackageName,
                                mRequestAdapter.getRequestBundleForGetAccounts(
                                        parameters,
                                        negotiatedBrokerProtocolVersion
                                ));
                    }

                    @Override
                    public @NonNull List<ICacheRecord> extractResultBundle(@Nullable final Bundle resultBundle) throws BaseException {
                        if (resultBundle == null) {
                            throw mResultAdapter.getExceptionForEmptyResultBundle();
                        }
                        return mResultAdapter.getAccountsFromResultBundle(resultBundle);
                    }

                    @Override
                    public @NonNull String getMethodName() {
                        return ":getAccounts";
                    }

                    @Override
                    public @NonNull String getTelemetryApiId() {
                        return TelemetryEventStrings.Api.BROKER_GET_ACCOUNTS;
                    }

                    @Override
                    public void putValueInSuccessEvent(ApiEndEvent event, List<ICacheRecord> result) {
                        event.put(TelemetryEventStrings.Key.ACCOUNTS_NUMBER, Integer.toString(result.size()));
                    }
                });
    }

    /**
     * Remove a given account from broker.
     *
     * @param parameters a {@link RemoveAccountCommandParameters}
     * @return true if the account is successfully removed.
     */
    @Override
    public boolean removeAccount(@NonNull final RemoveAccountCommandParameters parameters) throws BaseException {
        return mBrokerOperationExecutor.execute(parameters,
                new BrokerOperation<Boolean>() {
                    private String negotiatedBrokerProtocolVersion;

                    @Override
                    public void performPrerequisites(@NonNull final IIpcStrategy strategy) throws BaseException {
                        negotiatedBrokerProtocolVersion = hello(strategy, parameters);
                    }

                    @Override
                    public @NonNull BrokerOperationBundle getBundle() {
                        return new BrokerOperationBundle(
                                MSAL_REMOVE_ACCOUNT,
                                mActiveBrokerPackageName,
                                mRequestAdapter.getRequestBundleForRemoveAccount(
                                        parameters,
                                        negotiatedBrokerProtocolVersion
                                ));
                    }

                    @Override
                    public @NonNull Boolean extractResultBundle(@Nullable final Bundle resultBundle) throws BaseException {
                        mResultAdapter.verifyRemoveAccountResultFromBundle(resultBundle);
                        return true;
                    }

                    @Override
                    public @NonNull String getMethodName() {
                        return ":removeAccount";
                    }

                    @Override
                    public @NonNull String getTelemetryApiId() {
                        return TelemetryEventStrings.Api.BROKER_REMOVE_ACCOUNT;
                    }

                    @Override
                    public void putValueInSuccessEvent(ApiEndEvent event, Boolean result) {
                    }
                });
    }

    /**
     * Get device mode from broker.
     *
     * @param parameters a {@link CommandParameters}
     * @return true if the device is in as shared mode. False otherwise.
     */
    @Override
    public boolean getDeviceMode(@NonNull final CommandParameters parameters) throws BaseException {
        return mBrokerOperationExecutor.execute(parameters,
                new BrokerOperation<Boolean>() {
                    @Override
                    public void performPrerequisites(@NonNull final IIpcStrategy strategy) {
                    }

                    @Override
                    public @NonNull BrokerOperationBundle getBundle() {
                        return new BrokerOperationBundle(
                                MSAL_GET_DEVICE_MODE,
                                mActiveBrokerPackageName,
                                null);
                    }

                    @Override
                    public @NonNull Boolean extractResultBundle(@Nullable Bundle resultBundle) throws BaseException {
                        if (resultBundle == null) {
                            throw mResultAdapter.getExceptionForEmptyResultBundle();
                        }
                        return mResultAdapter.getDeviceModeFromResultBundle(resultBundle);
                    }

                    @Override
                    public @NonNull String getMethodName() {
                        return ":getDeviceMode";
                    }

                    @Override
                    public @NonNull String getTelemetryApiId() {
                        return TelemetryEventStrings.Api.GET_BROKER_DEVICE_MODE;
                    }

                    @Override
                    public void putValueInSuccessEvent(ApiEndEvent event, Boolean result) {
                        event.put(TelemetryEventStrings.Key.IS_DEVICE_SHARED, Boolean.toString(result));
                    }
                });
    }

    /**
     * If the device is in shared mode, returns the account that is currently signed into the device.
     * Otherwise, this will be the same as getAccounts().
     *
     * @param parameters a {@link CommandParameters}
     * @return a list of {@link ICacheRecord}.
     */
    @Override
    public @NonNull List<ICacheRecord> getCurrentAccount(@NonNull final CommandParameters parameters) throws BaseException {
        final String methodName = ":getCurrentAccount";

        if (!parameters.isSharedDevice()) {
            Logger.verbose(TAG + methodName, "Not a shared device, invoke getAccounts() instead of getCurrentAccount()");
            return getAccounts(parameters);
        }

        return mBrokerOperationExecutor.execute(parameters,
                new BrokerOperation<List<ICacheRecord>>() {
                    private String negotiatedBrokerProtocolVersion;

                    @Override
                    public void performPrerequisites(@NonNull final IIpcStrategy strategy) throws BaseException {
                        negotiatedBrokerProtocolVersion = hello(strategy, parameters);
                    }

                    @Override
                    public @NonNull BrokerOperationBundle getBundle() {
                        return new BrokerOperationBundle(
                                MSAL_GET_CURRENT_ACCOUNT_IN_SHARED_DEVICE,
                                mActiveBrokerPackageName,
                                mRequestAdapter.getRequestBundleForGetAccounts(
                                        parameters,
                                        negotiatedBrokerProtocolVersion
                                ));
                    }

                    @Override
                    public @NonNull List<ICacheRecord> extractResultBundle(@Nullable Bundle resultBundle) throws BaseException {
                        if (resultBundle == null) {
                            throw mResultAdapter.getExceptionForEmptyResultBundle();
                        }
                        return mResultAdapter.getAccountsFromResultBundle(resultBundle);
                    }

                    @Override
                    public @NonNull String getMethodName() {
                        return methodName;
                    }

                    @Override
                    public @NonNull String getTelemetryApiId() {
                        return TelemetryEventStrings.Api.BROKER_GET_CURRENT_ACCOUNT;
                    }

                    @Override
                    public void putValueInSuccessEvent(ApiEndEvent event, List<ICacheRecord> result) {
                        event.put(TelemetryEventStrings.Key.ACCOUNTS_NUMBER, Integer.toString(result.size()));
                    }
                });
    }

    /**
     * If the device is in shared mode, remove the account that is currently signed into the device.
     * Otherwise, this will be the same as removeAccount().
     *
     * @param parameters a {@link RemoveAccountCommandParameters}
     * @return a list of {@link ICacheRecord}.
     */
    @Override
    public boolean removeCurrentAccount(@NonNull final RemoveAccountCommandParameters parameters) throws BaseException {
        final String methodName = ":removeCurrentAccount";

        if (!parameters.isSharedDevice()) {
            Logger.verbose(TAG + methodName, "Not a shared device, invoke removeAccount() instead of removeCurrentAccount()");
            return removeAccount(parameters);
        }

        /*
         * Given an account, perform a global sign-out from this shared device (End my shift capability).
         * This will invoke Broker and
         * 1. Remove account from token cache.
         * 2. Remove account from AccountManager.
         * 3. Clear WebView cookies.
         *
         * If everything succeeds on the broker side, it will then
         * 4. Sign out from default browser.
         */
        return mBrokerOperationExecutor.execute(parameters,
                new BrokerOperation<Boolean>() {
                    private String negotiatedBrokerProtocolVersion;

                    @Override
                    public void performPrerequisites(@NonNull final IIpcStrategy strategy) throws BaseException {
                        negotiatedBrokerProtocolVersion = hello(strategy, parameters);
                    }

                    @Override
                    public @NonNull BrokerOperationBundle getBundle() {
                        return new BrokerOperationBundle(
                                MSAL_SIGN_OUT_FROM_SHARED_DEVICE,
                                mActiveBrokerPackageName,
                                mRequestAdapter.getRequestBundleForRemoveAccountFromSharedDevice(
                                        parameters,
                                        negotiatedBrokerProtocolVersion
                                ));
                    }

                    @Override
                    public @NonNull Boolean extractResultBundle(@Nullable Bundle resultBundle) throws BaseException {
                        mResultAdapter.verifyRemoveAccountResultFromBundle(resultBundle);
                        logOutFromBrowser(mApplicationContext, parameters);
                        return true;
                    }

                    @Override
                    public @NonNull String getMethodName() {
                        return methodName;
                    }

                    @Override
                    public @NonNull String getTelemetryApiId() {
                        return TelemetryEventStrings.Api.BROKER_REMOVE_ACCOUNT_FROM_SHARED_DEVICE;
                    }

                    @Override
                    public void putValueInSuccessEvent(ApiEndEvent event, Boolean result) {
                    }
                });
    }

    /**
     * Invoke the logout endpoint on the specified browser.
     * If there are more than 1 session in the browser, an account picker will be displayed.
     * (Alternatively, we could pass the optional sessionID as one of the query string parameter, but we're not storing that at the moment).
     *
     * @param context    {@link Context} application context.
     * @param parameters a {@link RemoveAccountCommandParameters}.
     */
    private void logOutFromBrowser(@NonNull final Context context,
                                   @NonNull final RemoveAccountCommandParameters parameters) {
        final String methodName = ":logOutFromBrowser";

        String browserPackageName = null;
        try {
            final Browser browser = BrowserSelector.select(context, parameters.getBrowserSafeList());
            browserPackageName = browser.getPackageName();
        } catch (final ClientException e) {
            // Best effort. If none is passed to broker, then it will let the OS decide.
            Logger.error(TAG, e.getErrorCode(), e);
        }

        try {
            final Intent intent = new Intent(Intent.ACTION_VIEW);
            intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            intent.setData(Uri.parse(AuthenticationConstants.Browser.LOGOUT_ENDPOINT_V2));
            if (browserPackageName != null) {
                intent.setPackage(browserPackageName);
            }
            context.startActivity(intent);

        } catch (final ActivityNotFoundException e) {
            Logger.error(TAG + methodName,
                    "Failed to launch browser sign out with browser=[" + browserPackageName + "]. Skipping.", e);
        }
    }

    // Suppressing rawtype warnings due to the generic type AuthorizationResult
    @SuppressWarnings(WarningType.rawtype_warning)
    @Override
    public AuthorizationResult deviceCodeFlowAuthRequest(DeviceCodeFlowCommandParameters parameters) throws ClientException {
        throw new ClientException("deviceCodeFlowAuthRequest() not supported in BrokerMsalController");
    }

    @Override
    public AcquireTokenResult acquireDeviceCodeFlowToken(@SuppressWarnings(WarningType.rawtype_warning) AuthorizationResult authorizationResult, DeviceCodeFlowCommandParameters commandParameters) throws ClientException {
        throw new ClientException("acquireDeviceCodeFlowToken() not supported in BrokerMsalController");
    }

    /**
     * Checks if the account returns is a MSA Account and sets single on state in cache
     */
    private void saveMsaAccountToCache(@NonNull final Bundle resultBundle,
                                       @SuppressWarnings(WarningType.rawtype_warning) @NonNull final MsalOAuth2TokenCache msalOAuth2TokenCache) throws BaseException {
        final String methodName = ":saveMsaAccountToCache";

        final BrokerResult brokerResult = new MsalBrokerResultAdapter().brokerResultFromBundle(resultBundle);

        if (resultBundle.getBoolean(AuthenticationConstants.Broker.BROKER_REQUEST_V2_SUCCESS) &&
                AzureActiveDirectoryAudience.MSA_MEGA_TENANT_ID.equalsIgnoreCase(brokerResult.getTenantId())) {
            Logger.info(TAG + methodName, "Result returned for MSA Account, saving to cache");

            if (StringUtil.isEmpty(brokerResult.getClientInfo())) {
                Logger.error(TAG + methodName, "ClientInfo is empty.", null);
                throw new ClientException(ErrorStrings.UNKNOWN_ERROR, "ClientInfo is empty.");
            }

            try {
                final ClientInfo clientInfo = new ClientInfo(brokerResult.getClientInfo());
                final MicrosoftStsAccount microsoftStsAccount = new MicrosoftStsAccount(
                        new IDToken(brokerResult.getIdToken()),
                        clientInfo
                );
                microsoftStsAccount.setEnvironment(brokerResult.getEnvironment());

                final MicrosoftRefreshToken microsoftRefreshToken = new MicrosoftRefreshToken(
                        brokerResult.getRefreshToken(),
                        clientInfo,
                        brokerResult.getScope(),
                        brokerResult.getClientId(),
                        brokerResult.getEnvironment(),
                        brokerResult.getFamilyId()
                );

                msalOAuth2TokenCacheSetSingleSignOnState(msalOAuth2TokenCache, microsoftStsAccount, microsoftRefreshToken);
            } catch (ServiceException e) {
                Logger.errorPII(TAG + methodName, "Exception while creating Idtoken or ClientInfo," +
                        " cannot save MSA account tokens", e
                );
                throw new ClientException(ErrorStrings.INVALID_JWT, e.getMessage(), e);
            }
        }

    }

    // Suppressing unchecked warnings due to casting of MicrosoftStsAccount to GenericAccount and MicrosoftRefreshToken to GenericRefreshToken in the call to setSingleSignOnState method
    @SuppressWarnings(WarningType.unchecked_warning)
    private void msalOAuth2TokenCacheSetSingleSignOnState(@SuppressWarnings(WarningType.rawtype_warning) @NonNull MsalOAuth2TokenCache msalOAuth2TokenCache, MicrosoftStsAccount microsoftStsAccount, MicrosoftRefreshToken microsoftRefreshToken) throws ClientException {
        msalOAuth2TokenCache.setSingleSignOnState(microsoftStsAccount, microsoftRefreshToken);
    }
}
