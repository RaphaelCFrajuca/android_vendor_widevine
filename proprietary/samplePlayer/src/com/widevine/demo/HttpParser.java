/*
 * (c)Copyright 2011 Widevine Technologies, Inc
 */

package com.widevine.demo;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.util.ArrayList;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;

public class HttpParser extends Thread {

    private ArrayList<AssetItem> assets;
    private String urlString;
    private String rootUrl;

    public HttpParser(String urlString) {
        this.urlString = urlString;
        this.assets = new ArrayList<AssetItem>();
        this.rootUrl = this.urlString.substring(0, this.urlString.lastIndexOf("/") + 1);
    }

    public void run() {

        try {

            DefaultHttpClient httpClient = new DefaultHttpClient();
            HttpGet request = new HttpGet(urlString);
            HttpResponse response = httpClient.execute(request);

            InputStream reader = response.getEntity().getContent();

            StringBuffer buffer = new StringBuffer();
            int data = 0;
            do {
                data = reader.read();
                if (data == -1) {
                    break;
                }
                buffer.append((char) data);

            } while (true);

            if (urlString.contains(".htm")) {
                parseHtml(buffer.toString());
            } else if (urlString.contains(".xml")) {
                parseXML(buffer.toString());
            }

        } catch (MalformedURLException e) {

        } catch (IOException e) {

        }
    }

    private void parseXML(String xmlText) {
        ConfigXMLParser parser = new ConfigXMLParser(new ByteArrayInputStream(xmlText.getBytes()));

        ArrayList<AssetDescriptor> descrs = (ArrayList<AssetDescriptor>) parser.parse();

        for (int i = 0; i < descrs.size(); i++) {
            AssetDescriptor asset = descrs.get(i);
            String imagePath = asset.getThumbnail();
            if (!imagePath.contains("http")) {
                imagePath = rootUrl + imagePath;
            }
            assets.add(new AssetItem(asset.getUri(), asset.getThumbnail(), asset.getTitle()));
        }
    }

    private void parseHtml(String htmlText) {
        int start = 0;
        int end = 0;

        while (true) {
            String assetPath = null;
            String title = null;
            String imagePath = null;
            start = htmlText.indexOf("href=\"", start);
            if (start == -1) {
                break;
            } else {
                start += "href=\"".length();
                end = htmlText.indexOf("\"", start);
                assetPath = htmlText.substring(start, end);
                start = end + 1;
                start = htmlText.indexOf("\"", start) + 1;
                end = htmlText.indexOf("\"", start);
                imagePath = htmlText.substring(start, end);
                if (!imagePath.contains("http") && !imagePath.contains("wvplay")) {
                    imagePath = rootUrl + imagePath;
                }
                start = htmlText.indexOf("<p>", start) + "<p>".length();
                end = htmlText.indexOf("</p>", start);
                title = htmlText.substring(start, end);
                start = end + 1;
                assets.add(new AssetItem(assetPath, imagePath, title));
            }
        }
    }

    public ArrayList<AssetItem> getAssets() {
        return this.assets;
    }
}
