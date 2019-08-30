/*
 * (c)Copyright 2011 Widevine Technologies, Inc
 */

package com.widevine.demo;

/**
 * Describes one asset in the list view
 */
public class AssetDescriptor {
    private String mThumbnail;
    private String mTitle;
    private String mDescription;
    private String mUri;
    private String mStatus;

    public AssetDescriptor copy() {
        AssetDescriptor ad = new AssetDescriptor();
        ad.setTitle(mTitle);
        ad.setThumbnail(mThumbnail);
        ad.setDescription(mDescription);
        ad.setUri(mUri);
        return ad;
    }

    public String getThumbnail() {
        return mThumbnail;
    }

    public void setThumbnail(String thumbnail) {
        mThumbnail = thumbnail;
    }

    public String getTitle() {
        return mTitle;
    }

    public void setTitle(String title) {
        mTitle = title;
    }

    public String getDescription() {
        return mDescription;
    }

    public void setDescription(String description) {
        mDescription = description;
    }

    public String getUri() {
        return mUri;
    }

    public void setUri(String uri) {
        mUri = uri;
    }

    public String getStatus() {
        return mStatus;
    }

    public void setStatus(String status) {
        mStatus = status;
    }
}
