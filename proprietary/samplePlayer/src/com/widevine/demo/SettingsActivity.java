/*
 * (c)Copyright 2011 Widevine Technologies, Inc
 */

package com.widevine.demo;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.os.Bundle;

import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.util.Log;

import android.content.Context;

public class SettingsActivity extends Activity {
    // public static String CONTENT_PAGE = "/sdcard/Widevine/config.xml";
    public static String CONTENT_PAGE = "http://seawwws001.shibboleth.tv/android/oem.html";

    private Context context;
    private Button updateButton;
    private EditText drmServer, portalName, deviceId, contentPage;

    public static final String TAG = "WVM Player Settings";

    @Override
    public void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);

        context = this;

        setContentView(R.layout.settings);

        updateButton = (Button) findViewById(R.id.update_button);

        View.OnClickListener clickListener = new View.OnClickListener() {

            public void onClick(View v) {
                Log.d(TAG, "Click update settings");
                WidevineDrm.Settings.DRM_SERVER_URI = drmServer.getText().toString();
                WidevineDrm.Settings.DEVICE_ID = deviceId.getText().toString();
                WidevineDrm.Settings.PORTAL_NAME = portalName.getText().toString();
                SettingsActivity.CONTENT_PAGE = contentPage.getText().toString();

                AlertDialog.Builder builder = new AlertDialog.Builder(context);
                builder.setMessage("DRM Settings Updated").setCancelable(false)
                        .setPositiveButton("Ok", new DialogInterface.OnClickListener() {
                            public void onClick(DialogInterface dialog, int id) {
                                Log.d(TAG, "Click DRM Settings OK.");
                                dialog.cancel();
                            }
                        });
                AlertDialog alert = builder.create();
                alert.show();
            }
        };

        updateButton.setOnClickListener(clickListener);

        drmServer = (EditText) findViewById(R.id.drm_server);
        drmServer.setText(WidevineDrm.Settings.DRM_SERVER_URI);

        deviceId = (EditText) findViewById(R.id.device_id);
        deviceId.setText(WidevineDrm.Settings.DEVICE_ID);

        portalName = (EditText) findViewById(R.id.portal_id);
        portalName.setText(WidevineDrm.Settings.PORTAL_NAME);

        contentPage = (EditText) findViewById(R.id.content_page);
        contentPage.setText(SettingsActivity.CONTENT_PAGE);

    }

}
