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
package com.microsoft.identity.internal.testutils;

import androidx.annotation.Nullable;

import com.microsoft.identity.common.java.net.AbstractHttpClient;
import com.microsoft.identity.common.java.net.HttpClient;
import com.microsoft.identity.common.java.net.HttpResponse;
import com.microsoft.identity.common.java.net.UrlConnectionHttpClient;
import com.microsoft.identity.internal.testutils.HttpRequestInterceptor;
import com.microsoft.identity.internal.testutils.MockHttpClient;

import java.io.IOException;
import java.net.URL;
import java.util.Map;

import javax.net.ssl.SSLContext;

import lombok.NonNull;

/**
 * A client that wraps around another client, allowing the use of {@link HttpRequestInterceptor}
 */
public class InterceptedHttpClient extends AbstractHttpClient {
    private final HttpClient mClient;

    public InterceptedHttpClient(@NonNull final HttpClient httpClient) {
        mClient = httpClient;
    }

    @Override
    public HttpResponse method(@NonNull final HttpMethod httpMethod,
                               @NonNull final URL requestUrl,
                               @NonNull final Map<String, String> requestHeaders,
                               @Nullable final byte[] requestContent,
                               @Nullable final SSLContext sslContext) throws IOException {
        final HttpRequestInterceptor interceptor = MockHttpClient.getInterceptor(httpMethod, requestUrl, requestHeaders, requestContent);
        if (interceptor == null) {
            return mClient.method(httpMethod, requestUrl, requestHeaders, requestContent, sslContext);
        } else {
            return interceptor.performIntercept(httpMethod, requestUrl, requestHeaders, requestContent);
        }
    }
}
