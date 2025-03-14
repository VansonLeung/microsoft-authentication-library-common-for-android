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
package com.microsoft.identity.common.internal.authorities;

import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.microsoft.identity.common.java.authorities.AccountsInOneOrganization;
import com.microsoft.identity.common.java.authorities.AllAccounts;
import com.microsoft.identity.common.java.authorities.AnyOrganizationalAccount;
import com.microsoft.identity.common.java.authorities.AnyPersonalAccount;
import com.microsoft.identity.common.java.authorities.AzureActiveDirectoryAudience;
import com.microsoft.identity.common.logging.Logger;

import net.jcip.annotations.Immutable;

import java.lang.reflect.Type;

@Immutable
public class AzureActiveDirectoryAudienceDeserializer implements JsonDeserializer<AzureActiveDirectoryAudience> {

    private static final String TAG = AzureActiveDirectoryAudienceDeserializer.class.getSimpleName();

    @Override
    public AzureActiveDirectoryAudience deserialize(final JsonElement json,
                                                    final Type typeOfT,
                                                    final JsonDeserializationContext context) throws JsonParseException {
        final String methodName = ":deserialize";
        JsonObject audienceObject = json.getAsJsonObject();
        JsonElement type = audienceObject.get("type");

        if (type != null) {
            switch (type.getAsString()) {
                case "AzureADMyOrg":
                    Logger.verbose(
                            TAG + methodName,
                            "Type: AzureADMyOrg"
                    );
                    return context.deserialize(audienceObject, AccountsInOneOrganization.class);
                case "AzureADMultipleOrgs":
                    Logger.verbose(
                            TAG + methodName,
                            "Type: AzureADMultipleOrgs"
                    );
                    return context.deserialize(audienceObject, AnyOrganizationalAccount.class);
                case "AzureADandPersonalMicrosoftAccount":
                    Logger.verbose(
                            TAG + methodName,
                            "Type: AzureADandPersonalMicrosoftAccount"
                    );
                    return context.deserialize(audienceObject, AllAccounts.class);
                case "PersonalMicrosoftAccount":
                    Logger.verbose(
                            TAG + methodName,
                            "Type: PersonalMicrosoftAccount"
                    );
                    return context.deserialize(audienceObject, AnyPersonalAccount.class);
                default:
                    Logger.verbose(
                            TAG + methodName,
                            "Type: Unknown"
                    );
                    return context.deserialize(audienceObject, UnknownAudience.class);
            }
        }

        return null;
    }
}
