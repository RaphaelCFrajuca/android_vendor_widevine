/*
 * (c)Copyright 2011 Widevine Technologies, Inc
 */

package com.widevine.demo;

import java.io.IOException;
import java.net.MalformedURLException;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;

public class ImageHandler extends Thread {

    private boolean scale;
    private String imageUrl;
    private Bitmap clipImage = null;

    public ImageHandler(String imageUrl) {
        this.imageUrl = imageUrl;
        this.clipImage = null;
    }

    public void setScale(boolean scale) {
        this.scale = scale;
    }

    public void run() {

        try {

            DefaultHttpClient httpClient = new DefaultHttpClient();
            HttpGet request = new HttpGet(imageUrl);
            HttpResponse response = httpClient.execute(request);

            this.clipImage = BitmapFactory.decodeStream(response.getEntity().getContent());
            if (scale) {
                this.clipImage = Bitmap.createScaledBitmap(this.clipImage, 150, 200, false);
            }
        } catch (MalformedURLException e) {
            this.clipImage = null;
        } catch (IOException e) {
            this.clipImage = null;
        }

    }

    public Bitmap getBitmap() {
        return this.clipImage;
    }

}
