#!/bin/bash
echo =============================================
echo Starting ADB Daemon
echo =============================================
adb start-server
emulator @test -no-window -no-audio -no-snapshot -wipe-data &
sleep 30
gradle -version
echo =============================================
echo Running instrumented tests
echo =============================================
gradle common:connectedLocalDebugAndroidTest -i -Psugar=true

