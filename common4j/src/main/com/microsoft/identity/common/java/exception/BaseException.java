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
package com.microsoft.identity.common.java.exception;

import com.microsoft.identity.common.java.telemetry.ITelemetryAccessor;
import com.microsoft.identity.common.java.util.StringUtil;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

import edu.umd.cs.findbugs.annotations.Nullable;
import lombok.Getter;
import lombok.NonNull;
import lombok.experimental.Accessors;

public class BaseException extends Exception implements IErrorInformation, ITelemetryAccessor {

    public static final String sName = BaseException.class.getName();
    private static final long serialVersionUID = -5166242728507796770L;

    private static final TreeSet<String> nonCacheableErrorCodes = new TreeSet<>(
            Arrays.asList(
                    ErrorStrings.DEVICE_NETWORK_NOT_AVAILABLE,
                    ClientException.INTERRUPTED_OPERATION,
                    ClientException.INVALID_BROKER_BUNDLE,
                    ClientException.IO_ERROR));

    @Nullable
    private String mSpeRing;

    @Nullable
    private String mRefreshTokenAge;

    @Nullable
    private String mCliTelemErrorCode;

    @Nullable
    private String mCliTelemSubErrorCode;

    private String mErrorCode;

    private String mCorrelationId;

    // The username of the account that owns the flow.
    @Nullable
    private String mUsername;

    private final List<Map<String, String>> mTelemetry = new ArrayList<>();

    /**
     * {@link Exception#addSuppressed(Throwable)} requires API19 in Android, so we're creating our own.
     */
    @Getter
    @Accessors(prefix = "m")
    private final List<Exception> mSuppressedException = new ArrayList<>();

    public void addSuppressedException(@NonNull final Exception e) {
        mSuppressedException.add(e);
    }

    /**
     * Default constructor.
     */
    protected BaseException() {
    }

    /**
     * Initiates the detailed error code.
     *
     * @param errorCode The error code contained in the exception.
     */
    public BaseException(final String errorCode) {
        mErrorCode = errorCode;
    }

    /**
     * Initiates the {@link BaseException} with error code and error message.
     *
     * @param errorCode    The error code contained in the exception.
     * @param errorMessage The error message contained in the exception.
     */
    public BaseException(final String errorCode, final String errorMessage) {
        super(errorMessage);
        mErrorCode = errorCode;
    }

    /**
     * Initiates the {@link BaseException} with error code, error message and throwable.
     *
     * @param errorCode    The error code contained in the exception.
     * @param errorMessage The error message contained in the exception.
     * @param throwable    The {@link Throwable} contains the cause for the exception.
     */
    public BaseException(final String errorCode, final String errorMessage,
                         final Throwable throwable) {
        super(errorMessage, throwable);
        mErrorCode = errorCode;
    }

    /**
     * @return The error code for the exception, could be null. {@link BaseException} is the top level base exception, for the
     * constants value of all the error code.
     */
    public String getErrorCode() {
        return mErrorCode;
    }

    /**
     * {@inheritDoc}
     * Return the detailed description explaining why the exception is returned back.
     */
    @Override
    public String getMessage() {
        if (!StringUtil.isNullOrEmpty(super.getMessage())) {
            return super.getMessage();
        }

        return null;
    }

    @Nullable
    public String getSpeRing() {
        return mSpeRing;
    }

    public void setSpeRing(@Nullable final String speRing) {
        this.mSpeRing = speRing;
    }

    @Nullable
    public String getRefreshTokenAge() {
        return mRefreshTokenAge;
    }

    public void setRefreshTokenAge(@Nullable final String refreshTokenAge) {
        this.mRefreshTokenAge = refreshTokenAge;
    }

    @Nullable
    public String getCliTelemErrorCode() {
        return mCliTelemErrorCode;
    }

    public void setCliTelemErrorCode(@Nullable final String cliTelemErrorCode) {
        this.mCliTelemErrorCode = cliTelemErrorCode;
    }

    @Nullable
    public String getCliTelemSubErrorCode() {
        return mCliTelemSubErrorCode;
    }

    public void setCliTelemSubErrorCode(@Nullable final String cliTelemSubErrorCode) {
        this.mCliTelemSubErrorCode = cliTelemSubErrorCode;
    }

    @Nullable
    public String getCorrelationId() {
        return mCorrelationId;
    }

    public void setCorrelationId(@Nullable final String correlationId) {
        mCorrelationId = correlationId;
    }

    @Nullable
    public String getUsername() {
        return mUsername;
    }

    public void setUsername(@NonNull final String username) {
        this.mUsername = username;
    }

    public String getExceptionName() {
        return sName;
    }

    public boolean isCacheable() {
        //TODO : ADO 1373343 Add the whole transient exception category.
        return !nonCacheableErrorCodes.contains(mErrorCode);
    }

    /**
     * Set the telemetry on base exception.
     *
     * @param telemetry the {@link List<Map<String, String>>} containing telemetry data
     */
    public void setTelemetry(@NonNull final List<Map<String, String>> telemetry) {
        mTelemetry.addAll(telemetry);
    }

    @Override
    public List<Map<String, String>> getTelemetry() {
        return mTelemetry;
    }
}
