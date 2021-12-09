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
package com.microsoft.identity.common.internal.broker;

import android.accounts.AccountManager;
import android.accounts.AuthenticatorDescription;
import android.annotation.SuppressLint;
import android.content.Context;
import android.content.pm.PackageManager.NameNotFoundException;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.microsoft.identity.common.BuildConfig;
import com.microsoft.identity.common.adal.internal.AuthenticationConstants;
import com.microsoft.identity.common.java.exception.ClientException;
import com.microsoft.identity.common.java.exception.ErrorStrings;
import com.microsoft.identity.common.internal.util.PackageUtils;
import com.microsoft.identity.common.internal.util.StringUtil;
import com.microsoft.identity.common.logging.Logger;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import static com.microsoft.identity.common.java.AuthenticationConstants.Broker.BROKER_ACCOUNT_TYPE;
import static com.microsoft.identity.common.java.exception.ClientException.NO_SUCH_ALGORITHM;
import static com.microsoft.identity.common.java.exception.ErrorStrings.APP_PACKAGE_NAME_NOT_FOUND;
import static com.microsoft.identity.common.java.exception.ErrorStrings.BROKER_VERIFICATION_FAILED;

public class BrokerValidator {

    private static final String TAG = "BrokerValidator";

    private static boolean sShouldTrustDebugBrokers = BuildConfig.DEBUG;

    public static void setShouldTrustDebugBrokers(final boolean shouldTrustDebugBrokers) {
        if (!BuildConfig.DEBUG && shouldTrustDebugBrokers) {
            throw new RuntimeException("Cannot trust debug brokers in non-debug builds.");
        }
        BrokerValidator.sShouldTrustDebugBrokers = shouldTrustDebugBrokers;
    }

    public static boolean getShouldTrustDebugBrokers() {
        return sShouldTrustDebugBrokers;
    }

    private final Context mContext;

    /**
     * Constructs a new BrokerValidator.
     *
     * @param context The Context of the host application.
     */
    public BrokerValidator(final Context context) {
        mContext = context;
    }

    /**
     * Verifies that the installed broker package's signing certificate hash matches the known
     * release certificate hash.
     * <p>
     * If signature hash verification fails, this will throw a Client exception containing the cause of error, which could contain a list of mismatch hashes.
     *
     * @param brokerPackageName The broker package to inspect.
     * @return SignatureHash of brokerPackageName, if the verification succeeds..
     */
    public String verifySignatureAndThrow(final String brokerPackageName) throws ClientException {
        try {
            // Read all the certificates associated with the package name. In higher version of
            // android sdk, package manager will only returned the cert that is used to sign the
            // APK. Even a cert is claimed to be issued by another certificates, sdk will return
            // the signing cert. However, for the lower version of android, it will return all the
            // certs in the chain. We need to verify that the cert chain is correctly chained up.
            final List<X509Certificate> certs = readCertDataForBrokerApp(brokerPackageName);

            // Verify the cert list contains the cert we trust.
            final String signatureHash = PackageUtils.verifySignatureHash(certs, getValidBrokerSignatures());

            // Perform the certificate chain validation. If there is only one cert returned,
            // no need to perform certificate chain validation.
            if (certs.size() > 1) {
                PackageUtils.verifyCertificateChain(certs);
            }

            return signatureHash;
        } catch (NameNotFoundException e) {
            throw new ClientException(APP_PACKAGE_NAME_NOT_FOUND, e.getMessage(), e);
        } catch (NoSuchAlgorithmException e) {
            throw new ClientException(NO_SUCH_ALGORITHM, e.getMessage(), e);
        } catch (final IOException | GeneralSecurityException e) {
            throw new ClientException(BROKER_VERIFICATION_FAILED, e.getMessage(), e);
        }
    }

    /**
     * Verifies that the installed broker package's signing certificate hash matches the known
     * release certificate hash.
     *
     * @param brokerPackageName The broker package to inspect.
     * @return True if the certificate hash is known. False otherwise.
     */
    public boolean verifySignature(final String brokerPackageName) {
        final String methodName = ":verifySignature";
        try {
            return verifySignatureAndThrow(brokerPackageName) != null;
        } catch (final ClientException e) {
            Logger.error(TAG + methodName, e.getErrorCode() + ": " + e.getMessage(), e);
        }

        return false;
    }

    /**
     * Provides a Set of valid Broker apps based on whether debug broker should be trusted or not.
     *
     * @return a Set of {@link BrokerData}
     */
    public Set<BrokerData> getValidBrokers() {
        final Set<BrokerData> validBrokers = sShouldTrustDebugBrokers
                ? BrokerData.getAllBrokers()
                : BrokerData.getProdBrokers();

        return validBrokers;
    }

    /**
     * Get an iterator of access to valid broker signatures.
     *
     * @return an iterator of access to valid broker signatures.
     */
    public Iterator<String> getValidBrokerSignatures() {
        final Iterator<BrokerData> itr = getValidBrokers().iterator();
        return new Iterator<String>() {
            @Override
            public void remove() {
                throw new UnsupportedOperationException("Remove operations are not supported");
            }

            @Override
            public boolean hasNext() {
                return itr.hasNext();
            }

            @Override
            public String next() {
                return itr.next().signatureHash;
            }
        };
    }

    /**
     * Determines if the supplied package name correspond to a valid Broker app.
     *
     * @param packageName the package name of the broker app to validate
     * @return a boolean indicating if the app is a valid broker
     */
    public boolean isValidBrokerPackage(@NonNull final String packageName) {
        final Set<BrokerData> validBrokers = getValidBrokers();

        for (final BrokerData brokerData : validBrokers) {
            if (brokerData.packageName.equals(packageName) && verifySignature(packageName)) {
                return true;
            }
        }

        // package name and/or signature not matched so this is not a valid broker.
        return false;
    }

    @SuppressLint("PackageManagerGetSignatures")
    @SuppressWarnings("deprecation")
    private List<X509Certificate> readCertDataForBrokerApp(final String brokerPackageName)
            throws NameNotFoundException, ClientException, IOException,
            GeneralSecurityException {
        return PackageUtils.readCertDataForApp(brokerPackageName, mContext);
    }

    /**
     * Returns the package that is currently active relative to the Work Account custom account type
     * Note: either the company portal or the authenticator
     * <p>
     * There may be multiple packages containing the android authenticator implementation (custom account)
     * but there is only one entry for custom account type currently registered by the AccountManager.
     * If another app tries to install same authenticator (custom account type) type, it will
     * queue up and will be active after first one is uninstalled.
     *
     * @return String current active broker package name, null if no broker is available
     */
    @Nullable
    public String getCurrentActiveBrokerPackageName() {
        AuthenticatorDescription[] authenticators = AccountManager.get(mContext).getAuthenticatorTypes();
        for (AuthenticatorDescription authenticator : authenticators) {
            if (authenticator.type.equals(BROKER_ACCOUNT_TYPE)
                    && verifySignature(authenticator.packageName)) {
                return authenticator.packageName;
            }
        }
        return null;
    }

    public static boolean isValidBrokerRedirect(@Nullable final String redirectUri,
                                                @NonNull final Context context,
                                                @NonNull final String packageName) {
        final String methodName = ":isValidBrokerRedirect";
        final String expectedBrokerRedirectUri = getBrokerRedirectUri(context, packageName);
        boolean isValidBrokerRedirect = StringUtil.equalsIgnoreCase(redirectUri, expectedBrokerRedirectUri);
        if (packageName.equals(AuthenticationConstants.Broker.AZURE_AUTHENTICATOR_APP_PACKAGE_NAME)) {
            final PackageHelper info = new PackageHelper(context.getPackageManager());
            final String signatureDigest = info.getCurrentSignatureForPackage(packageName);
            if (BrokerData.MICROSOFT_AUTHENTICATOR_PROD.signatureHash.equals(signatureDigest)
                    || BrokerData.MICROSOFT_AUTHENTICATOR_DEBUG.signatureHash.equals(signatureDigest)) {
                // If the caller is the Authenticator, check if the redirect uri matches with either
                // the one generated with package name and signature or broker redirect uri.
                isValidBrokerRedirect |= StringUtil.equalsIgnoreCase(redirectUri, AuthenticationConstants.Broker.BROKER_REDIRECT_URI);
            }
        }

        if (!isValidBrokerRedirect) {
            Logger.error(
                    TAG + methodName,
                    "Broker redirect uri is invalid. Expected: "
                            + expectedBrokerRedirectUri
                            + " Actual: "
                            + redirectUri
                    ,
                    null
            );
        }

        return isValidBrokerRedirect;
    }

    /**
     * Helper method to get Broker Redirect Uri
     *
     * @param context
     * @param packageName
     * @return String Broker Redirect Uri
     */
    public static String getBrokerRedirectUri(final Context context, final String packageName) {
        final PackageHelper info = new PackageHelper(context.getPackageManager());
        final String signatureDigest = info.getCurrentSignatureForPackage(packageName);
        return PackageHelper.getBrokerRedirectUrl(packageName,
                signatureDigest);
    }
}
