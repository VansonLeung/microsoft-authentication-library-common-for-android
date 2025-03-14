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

import android.content.Context;
import android.os.Build;
import android.os.Bundle;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.test.platform.app.InstrumentationRegistry;

import com.google.gson.Gson;
import com.microsoft.identity.common.adal.internal.AuthenticationConstants;
import com.microsoft.identity.common.components.SettablePlatformComponents;
import com.microsoft.identity.common.exception.BrokerCommunicationException;
import com.microsoft.identity.common.internal.broker.ipc.BrokerOperationBundle;
import com.microsoft.identity.common.internal.broker.ipc.IIpcStrategy;
import com.microsoft.identity.common.java.commands.AcquirePrtSsoTokenResult;
import com.microsoft.identity.common.java.commands.parameters.AcquirePrtSsoTokenCommandParameters;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.util.Collections;
import java.util.List;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = {Build.VERSION_CODES.N}, shadows = {})
public class BrokerMsalControllerTest {
    /**
     * This test simulates a result calling the PrtSsoToken Api where everything goes well talking
     * to the broker.
     */
    @Test
    public void testPrtSsoToken() throws Exception {
        final String anAccountName = "anAccountName";
        final String aHomeAccountId = "aHomeAccountId";
        final String aLocalAccountId = "aLocalAccountId";
        final String aCorrelationId = "aCorrelationId";
        final String accountAuthority = "https://login.microsoft.com/anAuthority";
        final String ssoUrl = "https://a.url.that.we.need/that/has/a/path?one_useless_param&sso_nonce=aNonceToUse&anotherUselessParam=foo";
        final String aCookie = "aCookie";
        final SettablePlatformComponents components = SettablePlatformComponents.builder().build();
        BrokerMsalController controller = new BrokerMsalController(InstrumentationRegistry.getInstrumentation().getContext(), components) {
            @Override
            public String getActiveBrokerPackageName() {
                return "aBrokerPackage";
            }

            @NonNull
            @Override
            protected List<IIpcStrategy> getIpcStrategies(Context applicationContext, String activeBrokerPackageName) {
                return Collections.<IIpcStrategy>singletonList(new IIpcStrategy() {
                    @Nullable
                    @Override
                    public Bundle communicateToBroker(@NonNull BrokerOperationBundle bundle) throws BrokerCommunicationException {
                        Bundle retBundle = new Bundle();
                        if (bundle.getOperation().equals(BrokerOperationBundle.Operation.MSAL_HELLO)) {
                            retBundle.putString(AuthenticationConstants.Broker.NEGOTIATED_BP_VERSION_KEY, "7.0");
                        } else if (bundle.getOperation().equals(BrokerOperationBundle.Operation.MSAL_SSO_TOKEN)) {
                            AcquirePrtSsoTokenResult result = AcquirePrtSsoTokenResult.builder()
                                    .accountName(anAccountName)
                                    .localAccountId(aLocalAccountId)
                                    .homeAccountId(aHomeAccountId)
                                    .accountAuthority(accountAuthority)
                                    .cookieName("x-ms-RefreshTokenCredential")
                                    .cookieContent(aCookie)
                                    .telemetry(Collections.<String, Object>emptyMap())
                                    .build();

                            retBundle.putString(AuthenticationConstants.Broker.BROKER_GENERATE_SSO_TOKEN_RESULT, new Gson().toJson(result));
                        }
                        return retBundle;
                    }

                    @Override
                    public Type getType() {
                        return Type.CONTENT_PROVIDER;
                    }
                });
            }
        };
        AcquirePrtSsoTokenCommandParameters params = AcquirePrtSsoTokenCommandParameters.builder()
                .platformComponents(components)
                .correlationId(aCorrelationId)
                .accountName(anAccountName)
                .requestAuthority(accountAuthority)
                .ssoUrl(ssoUrl)
                .build();
        final AcquirePrtSsoTokenResult ssoTokenResult = controller.getSsoToken(params);
        Assert.assertEquals(accountAuthority, ssoTokenResult.getAccountAuthority());
        Assert.assertEquals(anAccountName, ssoTokenResult.getAccountName());
        Assert.assertEquals(aHomeAccountId, ssoTokenResult.getHomeAccountId());
        Assert.assertEquals(aLocalAccountId, ssoTokenResult.getLocalAccountId());
        Assert.assertEquals(aCookie, ssoTokenResult.getCookieContent());
        Assert.assertEquals("x-ms-RefreshTokenCredential", ssoTokenResult.getCookieName());
    }

}
