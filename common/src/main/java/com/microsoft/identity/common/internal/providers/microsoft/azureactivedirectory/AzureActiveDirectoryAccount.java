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
package com.microsoft.identity.common.internal.providers.microsoft.azureactivedirectory;

import android.support.annotation.NonNull;

import com.microsoft.identity.common.adal.internal.util.StringExtensions;
import com.microsoft.identity.common.internal.logging.Logger;
import com.microsoft.identity.common.internal.providers.microsoft.MicrosoftAccount;
import com.microsoft.identity.common.internal.providers.oauth2.IDToken;

import java.util.Map;

/**
 * Inherits from account and implements the getUniqueIdentifier method for returning a unique identifier for an AAD User
 * UTID, UID combined as a single identifier per current MSAL implementation
 */
public class AzureActiveDirectoryAccount extends MicrosoftAccount {

    private static final String TAG = AzureActiveDirectoryAccount.class.getSimpleName();

    public AzureActiveDirectoryAccount() {
        super();
    }

    /**
     * Constructor for AzureActiveDirectoryAccount object
     *
     * @param idToken Returned as part of the TokenResponse
     * @param uid     Returned via clientInfo of TokenResponse
     * @param uTid    Returned via ClientInfo of Token Response
     */
    public AzureActiveDirectoryAccount(@NonNull final IDToken idToken,
                                       final String uid,
                                       final String uTid) {
        super(idToken, uid, uTid);
        Logger.verbose(TAG, "Init: " + TAG);
    }

    /**
     * Creates an AzureActiveDirectoryAccount based on the contents of the IDToken and based on the contents of the ClientInfo JSON
     * returned as part of the TokenResponse
     *
     * @param idToken
     * @return
     */
    public static AzureActiveDirectoryAccount create(@NonNull final IDToken idToken,
                                                     @NonNull final ClientInfo clientInfo) {
        final String methodName = "create";
        Logger.entering(TAG, methodName, idToken, clientInfo);

        final String uid = clientInfo.getUid();
        final String uTid = clientInfo.getUtid();

        AzureActiveDirectoryAccount acct = new AzureActiveDirectoryAccount(idToken, uid, uTid);

        Logger.exiting(TAG, methodName, acct);

        return acct;
    }

    @Override
    public String getAuthorityType() {
        return "AAD";
    }

    @Override
    protected String getDisplayableId(Map<String, String> claims) {
        final String methodName = "getDisplayableId";
        Logger.entering(TAG, methodName, claims);

        String displayableId = null;

        if (!StringExtensions.isNullOrBlank(claims.get(AzureActiveDirectoryIdToken.UPN))) {
            Logger.info(TAG + ":" + methodName, "Returning upn as displayableId");
            displayableId = claims.get(AzureActiveDirectoryIdToken.UPN);
        } else if (!StringExtensions.isNullOrBlank(claims.get(AzureActiveDirectoryIdToken.EMAIL))) {
            Logger.info(TAG + ":" + methodName, "Returning email as displayableId");
            displayableId = claims.get(AzureActiveDirectoryIdToken.EMAIL);
        }

        Logger.exiting(TAG, methodName, displayableId);

        return displayableId;
    }

    @Override
    public String toString() {
        return "AzureActiveDirectoryAccount{} " + super.toString();
    }
}
