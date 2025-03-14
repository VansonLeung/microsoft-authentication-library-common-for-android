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
package com.microsoft.identity.common.internal.logging;

import com.google.gson.Gson;
import com.microsoft.identity.common.logging.Logger;

import java.util.HashMap;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

/**
 * This class is deprecated.
 *
 * @see com.microsoft.identity.common.java.logging.RequestContext
 */
@Deprecated
public class RequestContext extends HashMap<String, String> implements IRequestContext {

    private static final String TAG = RequestContext.class.getSimpleName();

    private static final Gson mGson = new Gson();

    private static boolean sLogDeprecationWarning = true;

    @SuppressFBWarnings("ST_WRITE_TO_STATIC_FROM_INSTANCE_METHOD")
    @Override
    public String toJsonString() {
        if (sLogDeprecationWarning) {
            // only log 1x
            sLogDeprecationWarning = false;
            Logger.warn(TAG, "This class is deprecated. "
                    + "Migrate usage to: com.microsoft.identity.common.logging.RequestContext");
        }

        return mGson.toJson(this);
    }
}
