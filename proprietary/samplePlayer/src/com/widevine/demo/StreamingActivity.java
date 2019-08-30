/*
 * (c)Copyright 2011 Widevine Technologies, Inc
 */

package com.widevine.demo;

import java.io.File;
import java.net.MalformedURLException;
import java.util.ArrayList;

import android.os.Bundle;

public class StreamingActivity extends AssetActivity {
    private String contentPage;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        contentPage = SettingsActivity.CONTENT_PAGE;
        super.onCreate(savedInstanceState);

    }

    @Override
    public void onResume() {
        super.onResume();

        if (!contentPage.equals(SettingsActivity.CONTENT_PAGE)) {
            contentPage = SettingsActivity.CONTENT_PAGE;
            initialize();
        }
    }

    protected boolean setUpAssetPages() {
        pages = new ArrayList<AssetsPage>();

        if (contentPage.contains(".htm")) {
            ArrayList<AssetItem> assets = getStreamingClipsHttp();

            if (assets == null || assets.size() == 0)
                return false;

            for (int i = 0; i < assets.size();) {
                AssetsPage page = new AssetsPage();
                for (int j = 0; j < AssetsPage.MAX_ITEMS && i < assets.size(); j++, i++) {
                    page.addPage(assets.get(i).getAssetPath(),
                    assets.get(i).getImagePath(), assets.get(i).getTitle());
                }
                pages.add(page);
            }
        } else {
            ArrayList<AssetDescriptor> assets = getStreamingClipsXml();

            if (assets == null || assets.size() == 0)
                return false;

            for (int i = 0; i < assets.size();) {
                AssetsPage page = new AssetsPage();
                for (int j = 0; j < AssetsPage.MAX_ITEMS && i < assets.size(); j++, i++) {
                    page.addPage(assets.get(i).getUri(), assets.get(i).getThumbnail(),
                    assets.get(i).getTitle());
                }
                pages.add(page);
            }
        }

        return true;
    }

    private ArrayList<AssetDescriptor> getStreamingClipsXml() {

        try {
            File file = new File(contentPage);
            if (file.exists()) {
                ConfigXMLParser parser = new ConfigXMLParser(file.toURL());

                ArrayList<AssetDescriptor> assets = (ArrayList<AssetDescriptor>) parser.parse();
                return assets;
            } else {
                return new ArrayList<AssetDescriptor>();
            }
        } catch (MalformedURLException e) {
            return new ArrayList<AssetDescriptor>();
        }

    }

    private ArrayList<AssetItem> getStreamingClipsHttp() {
        HttpParser parser = new HttpParser(contentPage);
        parser.start();
        try {
            parser.join();
        } catch (InterruptedException e) {
        }
        return parser.getAssets();
    }

}
