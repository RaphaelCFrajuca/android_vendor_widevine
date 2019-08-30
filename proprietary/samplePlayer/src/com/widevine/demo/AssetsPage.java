/*
 * (c)Copyright 2011 Widevine Technologies, Inc
 */

package com.widevine.demo;

import java.util.ArrayList;

public class AssetsPage {
    public static final int MAX_ITEMS = 6;

    private ArrayList<AssetItem> assets;

    public AssetsPage() {
        assets = new ArrayList<AssetItem>();
    }

    public void addPage(String assetPath, String imagePath, String title) {
        assets.add(new AssetItem(assetPath, imagePath, title));
    }

    public AssetItem getPage(int pageNumber) {
        return assets.get(pageNumber);
    }

    public int getPageCount() {
        return assets.size();
    }
}
