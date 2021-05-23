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
package com.microsoft.identity.labapi.utilities.authentication;

import com.microsoft.identity.internal.test.keyvault.ApiException;
import com.microsoft.identity.internal.test.keyvault.Configuration;
import com.microsoft.identity.internal.test.keyvault.api.SecretsApi;
import com.microsoft.identity.labapi.utilities.authentication.msal4j.Msal4jConfidentialAuthClient;

import lombok.NonNull;

public class LabApiAuthenticationClient implements IAccessTokenAccessor {

    private final static String SECRET_NAME_LAB_APP_ID = "LabVaultAppID";
    private final static String SECRET_NAME_LAB_APP_SECRET = "LabVaultAppSecret";
    private final static String SECRET_VERSION = "";
    private final static String KEY_VAULT_API_VERSION = "2016-10-01";
    private final static String SCOPE = "https://msidlab.com/.default";

    private final static String TENANT_ID = "72f988bf-86f1-41af-91ab-2d7cd011db47";

    private final static String AUTHORITY = "https://login.microsoftonline.com/" + TENANT_ID;

    private final IConfidentialAuthClient mConfidentialAuthClient;
    private final KeyVaultAuthenticationClient mKeyVaultAuthenticationClient;

    public LabApiAuthenticationClient(@NonNull final IConfidentialAuthClient confidentialAuthClient) {
        mConfidentialAuthClient = confidentialAuthClient;
        mKeyVaultAuthenticationClient = new KeyVaultAuthenticationClient(confidentialAuthClient);
    }

    public LabApiAuthenticationClient(@NonNull final IConfidentialAuthClient confidentialAuthClient,
                                      @NonNull final String clientSecret) {
        mConfidentialAuthClient = confidentialAuthClient;
        mKeyVaultAuthenticationClient = new KeyVaultAuthenticationClient(confidentialAuthClient, clientSecret);
    }

    public LabApiAuthenticationClient() {
        this(new Msal4jConfidentialAuthClient());
    }

    public LabApiAuthenticationClient(@NonNull final String clientSecret) {
        this(new Msal4jConfidentialAuthClient(), clientSecret);
    }

    @Override
    public String getAccessToken() throws AuthenticationException {
        final String accessTokenForKeyVault = mKeyVaultAuthenticationClient.getAccessToken();
        Configuration.getDefaultApiClient().setAccessToken(accessTokenForKeyVault);

        final String labAppId, labAppSecret;

        try {
            final SecretsApi secretsApi = new SecretsApi();
            labAppId = secretsApi.getSecret(
                    SECRET_NAME_LAB_APP_ID, SECRET_VERSION, KEY_VAULT_API_VERSION
            ).getValue();

            labAppSecret = secretsApi.getSecret(
                    SECRET_NAME_LAB_APP_SECRET, SECRET_VERSION, KEY_VAULT_API_VERSION
            ).getValue();
        } catch (ApiException e) {
            throw new AuthenticationException();
        }

        final TokenParameters tokenParameters = TokenParameters
                .builder()
                .clientId(labAppId)
                .authority(AUTHORITY)
                .scope(SCOPE)
                .build();

        final IAuthenticationResult authenticationResult = mConfidentialAuthClient.acquireToken(
                labAppSecret, tokenParameters
        );

        return authenticationResult.getAccessToken();
    }
}
