/*
 * (c)Copyright 2011 Widevine Technologies, Inc
 */

package com.widevine.demo;

public class AssetItem {
    private String assetPath;
    private String imagePath;
    private String title;

    public AssetItem() {
        assetPath = null;
        imagePath = null;
        title = null;
    }

    public AssetItem(String assetPath, String imagePath, String title) {
        this.assetPath = assetPath;
        this.imagePath = imagePath;
        this.title = title;
    }

    public String getAssetPath() {
        return assetPath;
    }

    public String getImagePath() {
        return imagePath;
    }

    public String getTitle() {
        return title;
    }
}
