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
package com.microsoft.identity.common.java.logging;

import com.microsoft.identity.common.java.util.StringUtil;
import com.microsoft.identity.common.java.util.ThrowableUtil;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.TimeZone;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import lombok.Synchronized;
import lombok.experimental.Accessors;

public class Logger {

    private static final ExecutorService sLogExecutor = Executors.newSingleThreadExecutor();
    private static final String DATE_FORMAT = "yyyy-MM-dd HH:mm:ss";
    private static final String UNSET = "UNSET";

    // Turn on the VERBOSE level logging by default.
    @Setter()
    @Getter()
    @Accessors(prefix = "s")
    private static LogLevel sLogLevel = LogLevel.VERBOSE;

    // Disable to log PII by default.
    @Setter()
    @Getter()
    @Accessors(prefix = "s")
    private static boolean sAllowPii = false;

    @Accessors(prefix = "s")
    private static String sPlatformString = "";

    private static final ReentrantReadWriteLock sLoggersLock = new ReentrantReadWriteLock();

    private static final Map<String, ILoggerCallback> sLoggers = new HashMap<>();

    /**
     * Set the platform string to be used when generating logs.
     *
     * @param platformString the platform string to set
     */
    @Synchronized
    public static void setPlatformString(String platformString) {
        Logger.sPlatformString = platformString;
    }

    /**
     * Enum class for LogLevel that the sdk recognizes.
     */
    public enum LogLevel {
        /**
         * Error level logging.
         */
        ERROR,
        /**
         * Warn level logging.
         */
        WARN,
        /**
         * Info level logging.
         */
        INFO,
        /**
         * Verbose level logging.
         */
        VERBOSE,
        /**
         * Undefined. Should be used in test only.
         */
        UNDEFINED,
    }

    // Visible for testing
    static synchronized void resetLogger() {
        sLoggersLock.writeLock().lock();
        try {
            sLoggers.clear();
            sAllowPii = false;
            sPlatformString = "";
            sLogLevel = LogLevel.VERBOSE;
        } finally {
            sLoggersLock.writeLock().unlock();
        }
    }

    public static boolean setLogger(@NonNull String identifier,
                                    ILoggerCallback callback) {
        sLoggersLock.writeLock().lock();
        try {
            if (callback == null) {
                sLoggers.remove(identifier);
                return true;
            }

            if (sLoggers.containsValue(callback)){
                return false;
            }

            sLoggers.put(identifier, callback);
            return true;
        } finally {
            sLoggersLock.writeLock().unlock();
        }
    }

    /**
     * Get only the required metadata from the DiagnosticContext
     * to plug it in the log lines.
     * Here we are considering the correlation_id and the thread_name.
     * The need for this is because DiagnosticContext contains additional metadata which is not always required to be logged.
     *
     * @return String The concatenation of thread_name and correlation_id to serve as the required metadata in the log lines.
     */
    public static synchronized String getDiagnosticContextMetadata() {
        String threadName = DiagnosticContext.INSTANCE.getRequestContext().get(DiagnosticContext.THREAD_NAME);
        String correlationId = DiagnosticContext.INSTANCE.getRequestContext().get(DiagnosticContext.CORRELATION_ID);

        if (StringUtil.isNullOrEmpty(threadName)) {
            threadName = UNSET;
        }
        if (StringUtil.isNullOrEmpty(correlationId)) {
            correlationId = UNSET;
        }

        return DiagnosticContext.THREAD_NAME + " : "
                + threadName + ", "
                + DiagnosticContext.CORRELATION_ID + " : "
                + correlationId;
    }

    /**
     * Send a {@link LogLevel#ERROR} log message without PII.
     *
     * @param tag          Used to identify the source of a log message.
     *                     It usually identifies the class or activity where the log call occurs.
     * @param errorMessage The error message to log.
     * @param exception    An exception to log
     */
    public static void error(final String tag,
                             final String errorMessage,
                             final Throwable exception) {
        log(tag, LogLevel.ERROR, getDiagnosticContextMetadata(), errorMessage, exception, false);
    }

    /**
     * Send a {@link LogLevel#ERROR} log message without PII.
     *
     * @param tag           Used to identify the source of a log message. It usually identifies the
     *                      class or activity where the log call occurs.
     * @param correlationID Unique identifier for a request or flow used to trace program execution.
     * @param errorMessage  The error message to log.
     * @param exception     An exception to log.
     */
    public static void error(final String tag,
                             final String correlationID,
                             final String errorMessage,
                             final Throwable exception) {
        log(tag, LogLevel.ERROR, correlationID, errorMessage, exception, false);
    }

    /**
     * Send a {@link LogLevel#ERROR} log message with PII.
     *
     * @param tag          Used to identify the source of a log message. It usually identifies the
     *                     class or activity where the log call occurs.
     * @param errorMessage The error message to log.
     * @param exception    An exception to log.
     */
    public static void errorPII(final String tag,
                                final String errorMessage,
                                final Throwable exception) {
        log(tag, LogLevel.ERROR, getDiagnosticContextMetadata(), errorMessage, exception, true);
    }

    /**
     * Send a {@link LogLevel#ERROR} log message with PII.
     *
     * @param tag           Used to identify the source of a log message. It usually identifies the
     *                      class or activity where the log call occurs.
     * @param correlationID Unique identifier for a request or flow used to trace program execution.
     * @param errorMessage  The error message to log.
     * @param exception     An exception to log.
     */
    public static void errorPII(final String tag,
                                final String correlationID,
                                final String errorMessage,
                                final Throwable exception) {
        log(tag, LogLevel.ERROR, correlationID, errorMessage, exception, true);
    }

    /**
     * Send a {@link LogLevel#WARN} log message without PII.
     *
     * @param tag     Used to identify the source of a log message. It usually identifies the class
     *                or activity where the log call occurs.
     * @param message The message to log.
     */
    public static void warn(final String tag,
                            final String message) {
        log(tag, LogLevel.WARN, getDiagnosticContextMetadata(), message, null, false);
    }

    /**
     * Send a {@link LogLevel#WARN} log message without PII.
     *
     * @param tag           Used to identify the source of a log message. It usually identifies the
     *                      class or activity where the log call occurs.
     * @param correlationID Unique identifier for a request or flow used to trace program execution.
     * @param message       The message to log.
     */
    public static void warn(final String tag,
                            final String correlationID,
                            final String message) {
        log(tag, LogLevel.WARN, correlationID, message, null, false);
    }

    /**
     * Send a {@link LogLevel#WARN} log message with PII.
     *
     * @param tag     Used to identify the source of a log message. It usually identifies the class
     *                or activity where the log call occurs.
     * @param message The message to log.
     */
    public static void warnPII(final String tag,
                               final String message) {
        log(tag, LogLevel.WARN, getDiagnosticContextMetadata(), message, null, true);
    }

    /**
     * Send a {@link LogLevel#WARN} log message with PII.
     *
     * @param tag           Used to identify the source of a log message. It usually identifies the
     *                      class or activity where the log call occurs.
     * @param correlationID Unique identifier for a request or flow used to trace program execution.
     * @param message       The message to log.
     */
    public static void warnPII(final String tag,
                               final String correlationID,
                               final String message) {
        log(tag, LogLevel.WARN, correlationID, message, null, true);
    }

    /**
     * Send a {@link Logger.LogLevel#INFO} log message without PII.
     *
     * @param tag     Used to identify the source of a log message. It usually identifies the class
     *                or activity where the log call occurs.
     * @param message The message to log.
     */
    public static void info(final String tag,
                            final String message) {
        log(tag, Logger.LogLevel.INFO, getDiagnosticContextMetadata(), message, null, false);
    }

    /**
     * * Send a {@link Logger.LogLevel#INFO} log message without PII.
     *
     * @param tag           Used to identify the source of a log message. It usually identifies the
     *                      class or activity where the log call occurs.
     * @param correlationID Unique identifier for a request or flow used to trace program execution.
     * @param message       The message to log.
     */
    public static void info(final String tag,
                            final String correlationID,
                            final String message) {
        log(tag, LogLevel.INFO, correlationID, message, null, false);
    }

    /**
     * Send a {@link LogLevel#INFO} log message with PII.
     *
     * @param tag     Used to identify the source of a log message. It usually identifies the class
     *                or activity where the log call occurs.
     * @param message The message to log.
     */
    public static void infoPII(final String tag,
                               final String message) {
        log(tag, LogLevel.INFO, getDiagnosticContextMetadata(), message, null, true);
    }

    /**
     * Send a {@link LogLevel#INFO} log message with PII.
     *
     * @param tag           Used to identify the source of a log message. It usually identifies the
     *                      class or activity where the log call occurs.
     * @param correlationID Unique identifier for a request or flow used to trace program execution.
     * @param message       The message to log.
     */
    public static void infoPII(final String tag,
                               final String correlationID,
                               final String message) {
        log(tag, LogLevel.INFO, correlationID, message, null, true);
    }

    /**
     * Send a {@link LogLevel#VERBOSE} log message without PII.
     *
     * @param tag     Used to identify the source of a log message. It usually identifies the class
     *                or activity where the log call occurs.
     * @param message The message to log.
     */
    public static void verbose(final String tag,
                               final String message) {
        log(tag, LogLevel.VERBOSE, getDiagnosticContextMetadata(), message, null, false);
    }

    /**
     * Send a {@link LogLevel#VERBOSE} log message without PII.
     *
     * @param tag           Used to identify the source of a log message. It usually identifies the
     *                      class or activity where the log call occurs.
     * @param correlationID Unique identifier for a request or flow used to trace program execution.
     * @param message       The message to log.
     */
    public static void verbose(final String tag,
                               final String correlationID,
                               final String message) {
        log(tag, LogLevel.VERBOSE, correlationID, message, null, false);
    }

    /**
     * Send a {@link LogLevel#VERBOSE} log message with PII.
     *
     * @param tag     Used to identify the source of a log message. It usually identifies the class
     *                or activity where the log call occurs.
     * @param message The message to log.
     */
    public static void verbosePII(final String tag,
                                  final String message) {
        log(tag, LogLevel.VERBOSE, getDiagnosticContextMetadata(), message, null, true);
    }

    /**
     * Send a {@link LogLevel#VERBOSE} log message with PII.
     *
     * @param tag           Used to identify the source of a log message. It usually identifies the
     *                      class or activity where the log call occurs.
     * @param correlationID Unique identifier for a request or flow used to trace program execution.
     * @param message       The message to log.
     */
    public static void verbosePII(final String tag,
                                  final String correlationID,
                                  final String message) {
        log(tag, LogLevel.VERBOSE, correlationID, message, null, true);
    }

    private static void log(final String tag,
                            @NonNull final LogLevel logLevel,
                            final String correlationID,
                            final String message,
                            final Throwable throwable,
                            final boolean containsPII) {

        final String dateTimeStamp = getUTCDateTimeAsString();

        sLogExecutor.execute(new Runnable() {
            @Override
            public void run() {
                //Format the log message.
                final String logMessage = formatMessage(correlationID, message, dateTimeStamp, throwable);

                sLoggersLock.readLock().lock();
                try {
                    for (final String loggerCallbackKey : sLoggers.keySet()) {
                        try {
                            final ILoggerCallback callback = sLoggers.get(loggerCallbackKey);
                            if (callback != null) {
                                if (logLevel.compareTo(sLogLevel) > 0) {
                                    logDiscardedLogIfApplicable(logMessage, callback, tag, logLevel, containsPII);
                                    return;
                                }

                                // Developer turns off PII logging, if the log message contains any PII,
                                // we should not send it.
                                if (!sAllowPii && containsPII) {
                                    logDiscardedLogIfApplicable(logMessage, callback, tag, logLevel, containsPII);
                                    return;
                                }

                                callback.log(tag, logLevel, logMessage, containsPII);
                            }
                        } catch (final Exception e) {
                            // Do nothing.
                        }
                    }
                } finally {
                    sLoggersLock.readLock().unlock();
                }
            }
        });
    }

    /**
     * If applicable, log the discarded log.
     * This is applicable for testing only (IDetailedLoggerCallback is package-private).
     */
    private static void logDiscardedLogIfApplicable(String logMessage, ILoggerCallback callback, @NonNull String tag, @NonNull Logger.LogLevel logLevel, boolean containsPII) {
        if (callback instanceof IDetailedLoggerCallback) {
            ((IDetailedLoggerCallback) callback).discardedLog(tag, logLevel, logMessage, containsPII);
        }
    }

    /**
     * Wrap the log message.
     * If correlation id exists:
     * <library_version> [<timestamp> - <correlation_id>] <log_message>
     * If correlation id doesn't exist:
     * <library_version> [<timestamp>] <log_message>
     */
    private static String formatMessage(final String correlationID,
                                        final String message,
                                        @NonNull final String dateTimeStamp,
                                        final Throwable throwable) {
        final String logMessage = StringUtil.isNullOrEmpty(message) ? "N/A" : message;
        return " [" + dateTimeStamp
                + (StringUtil.isNullOrEmpty(correlationID) ? "] " : " - " + correlationID + "] ")
                + sPlatformString + " "
                + logMessage
                + (throwable == null ? "" : '\n' + ThrowableUtil.getStackTraceAsString(throwable));
    }

    private static String getUTCDateTimeAsString() {
        final SimpleDateFormat dateFormat = new SimpleDateFormat(DATE_FORMAT, Locale.getDefault());
        dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));

        return dateFormat.format(new Date());
    }
}

