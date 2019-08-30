package com.widevine.test;

import android.media.MediaDrm;
import android.media.DeniedByServerException;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.HttpClient;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.HttpResponse;
import org.apache.http.util.EntityUtils;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import android.os.AsyncTask;
import android.util.Log;

public class ProvisionRequester {
    private final String TAG = "ProvisionRequester";

    public ProvisionRequester() {
    }

    public void doTransact(MediaDrm drm) {
        MediaDrm.ProvisionRequest drmRequest;
        drmRequest = drm.getProvisionRequest();

        PostRequestTask postTask = new PostRequestTask(drmRequest.getData());
        Log.i(TAG, "Attempting to provision from server '" + drmRequest.getDefaultUrl() + "'");
        postTask.execute(drmRequest.getDefaultUrl());

        // wait for post task to complete
        byte[] responseBody;
        long startTime = System.currentTimeMillis();
        do {
            responseBody = postTask.getResponseBody();
            if (responseBody == null) {
                sleep(100);
            } else {
                break;
            }
        } while (System.currentTimeMillis() - startTime < 5000);

        if (responseBody == null) {
            Log.e(TAG, "No response from provisioning server!");
        } else {
            try {
                drm.provideProvisionResponse(responseBody);
            } catch (DeniedByServerException e) {
                Log.e(TAG, "Server denied provisioning request");
            }
        }
    }

    private class PostRequestTask extends AsyncTask<String, Void, Void> {
        private final String TAG = "PostRequestTask";

        private byte[] mDrmRequest;
        private byte[] mResponseBody;

        public PostRequestTask(byte[] drmRequest) {
            mDrmRequest = drmRequest;
        }

        protected Void doInBackground(String... urls) {
            mResponseBody = postRequest(urls[0], mDrmRequest);
            if (mResponseBody != null) {
                Log.d(TAG, "response length=" + mResponseBody.length);
            }
            return null;
        }

        public byte[] getResponseBody() {
            return mResponseBody;
        }

        private byte[] postRequest(String url, byte[] drmRequest) {
            HttpClient httpclient = new DefaultHttpClient();
            HttpPost httppost = new HttpPost(url + "&signedRequest=" + new String(drmRequest));

            Log.d(TAG, "PostRequest:" + httppost.getRequestLine());

            try {
                // Add data
                httppost.setHeader("Accept", "*/*");
                httppost.setHeader("User-Agent", "Widevine CDM v1.0");
                httppost.setHeader("Content-Type", "application/json");

                // Execute HTTP Post Request
                HttpResponse response = httpclient.execute(httppost);

                byte[] responseBody;
                int responseCode = response.getStatusLine().getStatusCode();
                if (responseCode == 200) {
                    responseBody = EntityUtils.toByteArray(response.getEntity());
                } else {
                    Log.d(TAG, "Server returned HTTP error code " + responseCode);
                    return null;
                }
                return responseBody;

            } catch (ClientProtocolException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
            return null;
        }
    }

    private void sleep(int msec) {
        try {
            Thread.sleep(msec);
        } catch (InterruptedException e) {
        }
    }
}

