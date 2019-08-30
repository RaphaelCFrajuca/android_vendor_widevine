/*
 * (c)Copyright 2011 Widevine Technologies, Inc
 */

package com.widevine.demo;

import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.util.EventListener;
import java.util.Set;
import android.util.Log;

import android.content.ContentValues;
import android.content.Context;

import android.drm.DrmErrorEvent;
import android.drm.DrmEvent;
import android.drm.DrmInfo;
import android.drm.DrmInfoEvent;
import android.drm.DrmInfoRequest;
import android.drm.DrmManagerClient;
import android.drm.DrmStore;

public class WidevineDrm {

    public static final String TAG = "WVM Sample Player";

    interface WidevineDrmLogEventListener extends EventListener {
        public void logUpdated();
    }

    private WidevineDrmLogEventListener logEventListener;
    private final static long DEVICE_IS_PROVISIONED = 0;
    private final static long DEVICE_IS_NOT_PROVISIONED = 1;
    private final static long DEVICE_IS_PROVISIONED_SD_ONLY = 2;
    private long mWVDrmInfoRequestStatusKey = DEVICE_IS_PROVISIONED;
    private String mPluginVersion = "";

    public StringBuffer logBuffer = new StringBuffer();

    /**
     * Drm Manager Configuration Methods
     */

    public static class Settings {
        public static String WIDEVINE_MIME_TYPE = "video/wvm";
        public static String DRM_SERVER_URI = "https://wstfcps005.shibboleth.tv/widevine/cypherpc/cgi-bin/GetEMMs.cgi";
        public static String DEVICE_ID = "device12345"; // use a unique device ID
        public static String PORTAL_NAME = "OEM";

        // test with a sizeable block of user data...
        public static String USER_DATA = "01234567890123456789012345678901234567890123456789"
            + "01234567890123456789012345678901234567890123456789"
            + "01234567890123456789012345678901234567890123456789"
            + "01234567890123456789012345678901234567890123456789"
            + "01234567890123456789012345678901234567890123456789"
            + "01234567890123456789012345678901234567890123456789";
    };

    private DrmManagerClient mDrmManager;

    // private Context mContext;

    public WidevineDrm(Context context) {

        // mContext = context;
        mDrmManager = new DrmManagerClient(context);

        mDrmManager.setOnInfoListener(new DrmManagerClient.OnInfoListener() {
            // @Override
            public void onInfo(DrmManagerClient client, DrmInfoEvent event) {
                if (event.getType() == DrmInfoEvent.TYPE_RIGHTS_INSTALLED) {
                    logMessage("Rights installed\n");
                }
            }
        });

        mDrmManager.setOnEventListener(new DrmManagerClient.OnEventListener() {

            public void onEvent(DrmManagerClient client, DrmEvent event) {
                switch (event.getType()) {
                case DrmEvent.TYPE_DRM_INFO_PROCESSED:
                    logMessage("Info Processed\n");
                    break;
                case DrmEvent.TYPE_ALL_RIGHTS_REMOVED:
                    logMessage("All rights removed\n");
                    break;
                }
            }
        });

        mDrmManager.setOnErrorListener(new DrmManagerClient.OnErrorListener() {
            public void onError(DrmManagerClient client, DrmErrorEvent event) {
                switch (event.getType()) {
                case DrmErrorEvent.TYPE_NO_INTERNET_CONNECTION:
                    logMessage("No Internet Connection\n");
                    break;
                case DrmErrorEvent.TYPE_NOT_SUPPORTED:
                    logMessage("Not Supported\n");
                    break;
                case DrmErrorEvent.TYPE_OUT_OF_MEMORY:
                    logMessage("Out of Memory\n");
                    break;
                case DrmErrorEvent.TYPE_PROCESS_DRM_INFO_FAILED:
                    logMessage("Process DRM Info failed\n");
                    break;
                case DrmErrorEvent.TYPE_REMOVE_ALL_RIGHTS_FAILED:
                    logMessage("Remove All Rights failed\n");
                    break;
                case DrmErrorEvent.TYPE_RIGHTS_NOT_INSTALLED:
                    logMessage("Rights not installed\n");
                    break;
                case DrmErrorEvent.TYPE_RIGHTS_RENEWAL_NOT_ALLOWED:
                    logMessage("Rights renewal not allowed\n");
                    break;
                }

            }
        });
    }

    public DrmInfoRequest getDrmInfoRequest(String assetUri) {
        DrmInfoRequest rightsAcquisitionInfo;
        rightsAcquisitionInfo = new DrmInfoRequest(DrmInfoRequest.TYPE_RIGHTS_ACQUISITION_INFO,
                Settings.WIDEVINE_MIME_TYPE);

        rightsAcquisitionInfo.put("WVDRMServerKey", Settings.DRM_SERVER_URI);
        rightsAcquisitionInfo.put("WVAssetURIKey", assetUri);
        rightsAcquisitionInfo.put("WVDeviceIDKey", Settings.DEVICE_ID);
        rightsAcquisitionInfo.put("WVPortalKey", Settings.PORTAL_NAME);
        rightsAcquisitionInfo.put("WVCAUserDataKey", Settings.USER_DATA);

        return rightsAcquisitionInfo;
    }

    public DrmInfoRequest getDrmInfoRequest(String assetUri, FileDescriptor fd) {

        DrmInfoRequest rightsAcquisitionInfo = getDrmInfoRequest(assetUri);

        if (fd.valid()) {
            rightsAcquisitionInfo.put("FileDescriptorKey", fd.toString());
        }

        return rightsAcquisitionInfo;
    }

    public boolean isProvisionedDevice() {

        if (mWVDrmInfoRequestStatusKey == DEVICE_IS_PROVISIONED)
          logMessage("Device is provisioined\n");
        else if (mWVDrmInfoRequestStatusKey == DEVICE_IS_PROVISIONED_SD_ONLY)
          logMessage("Device is provisioined SD only\n");
        else if (mWVDrmInfoRequestStatusKey == DEVICE_IS_NOT_PROVISIONED)
          logMessage("Device is not provisioined\n");
        else
          logMessage("Invalid provisioned status=" + mWVDrmInfoRequestStatusKey +"\n");

        return ((mWVDrmInfoRequestStatusKey == DEVICE_IS_PROVISIONED) ||
                (mWVDrmInfoRequestStatusKey == DEVICE_IS_PROVISIONED_SD_ONLY));
    }

    public void printPluginVersion() {
        logMessage("plugin: " + mPluginVersion + "\n");
    }

    public void registerPortal(String portal) {

        DrmInfoRequest request = new DrmInfoRequest(DrmInfoRequest.TYPE_REGISTRATION_INFO,
                Settings.WIDEVINE_MIME_TYPE);
        request.put("WVPortalKey", portal);
        DrmInfo response = mDrmManager.acquireDrmInfo(request);

        String drmInfoRequestStatusKey = (String)response.get("WVDrmInfoRequestStatusKey");
        if (null != drmInfoRequestStatusKey && !drmInfoRequestStatusKey.equals("")) {
            mWVDrmInfoRequestStatusKey = Long.parseLong(drmInfoRequestStatusKey);
        }

        mPluginVersion = (String)response.get("WVDrmInfoRequestVersionKey");
    }

    public int acquireRights(String assetUri) {

        int rights = 0;
        if (assetUri.startsWith("/sdcard")) {
            try {
                FileInputStream fis = new FileInputStream(assetUri);
                FileDescriptor fd = fis.getFD();
                rights = mDrmManager.acquireRights(getDrmInfoRequest(assetUri, fd));
                fis.close();
            }
            catch (java.io.IOException e) {
                logMessage("Unable to acquire rights for '" + assetUri + ": File I/O error'\n");
            }
        } else {
            rights = mDrmManager.acquireRights(getDrmInfoRequest(assetUri));
        }

        logMessage("acquireRights = " + rights + "\n");

        return rights;
    }

    public int checkRightsStatus(String assetUri) {

        // Need to use acquireDrmInfo prior to calling checkRightsStatus
        mDrmManager.acquireDrmInfo(getDrmInfoRequest(assetUri));
        int status = mDrmManager.checkRightsStatus(assetUri);
        logMessage("checkRightsStatus  = " + status + "\n");

        return status;
    }

    public void getConstraints(String assetUri) {

        ContentValues values = mDrmManager.getConstraints(assetUri, DrmStore.Action.PLAY);
        logContentValues(values, "No Contraints");
    }

    public void showRights(String assetUri) {
        logMessage("showRights\n");

        // Need to use acquireDrmInfo prior to calling getConstraints
        mDrmManager.acquireDrmInfo(getDrmInfoRequest(assetUri));
        ContentValues values = mDrmManager.getConstraints(assetUri, DrmStore.Action.PLAY);
        logContentValues(values, "No Rights");

    }

    private void logContentValues(ContentValues values, String defaultMessage) {
        if (values != null) {

            Set<String> keys = values.keySet();
            for (String key : keys) {
                if (key.toLowerCase().contains("time")) {
                    logMessage(key + " = " + SecondsToDHMS(values.getAsLong(key)) + "\n");
                } else if (key.toLowerCase().contains("licensetype")) {
                    logMessage(key + " = " + licenseType(values.getAsInteger(key)) + "\n");
                } else if (key.toLowerCase().contains("licensedresolution")) {
                    logMessage(key + " = " + licenseResolution(values.getAsInteger(key)) + "\n");
                } else {
                    logMessage(key + " = " + values.get(key) + "\n");
                }
            }
        } else {
            logMessage(defaultMessage + "\n");
        }
    }

    private static final long seconds_per_minute = 60;
    private static final long seconds_per_hour = 60 * seconds_per_minute;
    private static final long seconds_per_day = 24 * seconds_per_hour;

    private String SecondsToDHMS(long seconds) {
        int days = (int) (seconds / seconds_per_day);
        seconds -= days * seconds_per_day;
        int hours = (int) (seconds / seconds_per_hour);
        seconds -= hours * seconds_per_hour;
        int minutes = (int) (seconds / seconds_per_minute);
        seconds -= minutes * seconds_per_minute;
        return Integer.toString(days) + "d " + Integer.toString(hours) + "h "
                                        + Integer.toString(minutes) + "m " + Long.toString(seconds)
                                        + "s";
    }

    private String licenseType(int code) {
        switch (code) {
        case 1:
            return "Streaming";
        case 2:
            return "Offline";
        case 3:
            return "Both";
        default:
            return "Unknown";
        }
    }

    private String licenseResolution(int code) {
        switch (code) {
        case 1:
            return "SD only";
        case 2:
            return "HD or SD content";
        default:
            return "Unknown";
        }
    }

    public int removeRights(String assetUri) {

        // Need to use acquireDrmInfo prior to calling removeRights
        mDrmManager.acquireDrmInfo(getDrmInfoRequest(assetUri));
        int removeStatus = mDrmManager.removeRights(assetUri);
        logMessage("removeRights = " + removeStatus + "\n");

        return removeStatus;
    }

    public int removeAllRights() {
        int removeAllStatus = mDrmManager.removeAllRights();
        logMessage("removeAllRights = " + removeAllStatus + "\n");
        return removeAllStatus;
    }

    public void setLogListener(WidevineDrmLogEventListener logEventListener) {
        this.logEventListener = logEventListener;
    }

    private void logMessage(String message) {
        Log.d(TAG, message);
        logBuffer.append(message);

        if (logEventListener != null) {
            logEventListener.logUpdated();
        }
    }
}
