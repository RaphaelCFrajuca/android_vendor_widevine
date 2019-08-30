/*
 * (c)Copyright 2011 Widevine Technologies, Inc
 */

package com.widevine.demo;

import android.app.TabActivity;
import android.os.Bundle;
import android.widget.TabHost;
import android.content.Intent;
import android.content.SharedPreferences;

public class WidevineSamplePlayer extends TabActivity {

    public static final String PREFS_NAME = "DrmPrefs";

    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);

        SharedPreferences settings = getSharedPreferences(PREFS_NAME, 0);
        WidevineDrm.Settings.DRM_SERVER_URI = settings.getString("drmServer",
                WidevineDrm.Settings.DRM_SERVER_URI);
        WidevineDrm.Settings.DEVICE_ID = settings.getString("deviceId",
                WidevineDrm.Settings.DEVICE_ID);
        WidevineDrm.Settings.PORTAL_NAME = settings.getString("portalId",
                WidevineDrm.Settings.PORTAL_NAME);
        SettingsActivity.CONTENT_PAGE = settings.getString("contentPage",
                SettingsActivity.CONTENT_PAGE);

        setContentView(R.layout.main);

        TabHost tab = getTabHost();

        // Setup Streaming tab
        TabHost.TabSpec streamingTab = tab.newTabSpec("Streaming");

        streamingTab.setIndicator("Streaming");

        Intent streamingIntent = new Intent(this, StreamingActivity.class);
        streamingTab.setContent(streamingIntent);

        tab.addTab(streamingTab);

        // Setup Down load tab
        TabHost.TabSpec downloadTab = tab.newTabSpec("Downloads");

        downloadTab.setIndicator("Downloads");

        Intent downloadIntent = new Intent(this, DownloadActivity.class);
        downloadTab.setContent(downloadIntent);

        tab.addTab(downloadTab);

        // Setup Settings tab
        TabHost.TabSpec settingsTab = tab.newTabSpec("Settings");

        settingsTab.setIndicator("Settings");

        Intent settingsIntent = new Intent(this, SettingsActivity.class);
        settingsTab.setContent(settingsIntent);

        tab.addTab(settingsTab);

    }

    @Override
    protected void onStop() {
        super.onStop();

        // We need an Editor object to make preference changes.
        // All objects are from android.context.Context
        SharedPreferences settings = getSharedPreferences(PREFS_NAME, 0);

        SharedPreferences.Editor editor = settings.edit();
        editor.putString("drmServer", WidevineDrm.Settings.DRM_SERVER_URI);
        editor.putString("deviceId", WidevineDrm.Settings.DEVICE_ID);
        editor.putString("portalId", WidevineDrm.Settings.PORTAL_NAME);
        editor.putString("contentPage", SettingsActivity.CONTENT_PAGE);
        // Commit the edits!
        editor.commit();
    }
}
