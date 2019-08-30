/*
 * (c)Copyright 2011 Widevine Technologies, Inc
 */

package com.widevine.demo;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import android.sax.Element;
import android.sax.EndElementListener;
import android.sax.EndTextElementListener;
import android.sax.RootElement;
import android.util.Xml;

/**
 * Parser for the XML configuration file that defines the assets available to
 * play
 */
public class ConfigXMLParser {

    private URL mFeedUrl;
    private InputStream inputStream;

    protected InputStream getInputStream() {
        try {
            if (inputStream != null)
                return inputStream;
            else
                return mFeedUrl.openConnection().getInputStream();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public ConfigXMLParser(URL feedUrl) {
        mFeedUrl = feedUrl;
    }

    public ConfigXMLParser(InputStream inputStream) {
        this.inputStream = inputStream;
    }

    public List<AssetDescriptor> parse() {
        final AssetDescriptor currentAssetDescriptor = new AssetDescriptor();
        RootElement root = new RootElement("widevine");
        final List<AssetDescriptor> assetDescriptors = new ArrayList<AssetDescriptor>();
        Element assetlist = root.getChild("asset-list");
        Element asset = assetlist.getChild("asset");
        asset.setEndElementListener(new EndElementListener() {
            public void end() {
                if (currentAssetDescriptor.getUri().indexOf(".wvm") != -1
                    || currentAssetDescriptor.getUri().indexOf(".ts") != -1
                    || currentAssetDescriptor.getUri().indexOf(".m3u8") != -1
                    || !currentAssetDescriptor.getUri().substring(currentAssetDescriptor
                            .getUri().lastIndexOf("/")).contains(".")) {
                    assetDescriptors.add(currentAssetDescriptor.copy());
                }
            }
        });
        asset.getChild("title").setEndTextElementListener(new EndTextElementListener() {
            public void end(String body) {
                currentAssetDescriptor.setTitle(body);
            }
        });
        asset.getChild("uri").setEndTextElementListener(new EndTextElementListener() {
            public void end(String body) {
                currentAssetDescriptor.setUri(body);
            }
        });
        asset.getChild("description").setEndTextElementListener(new EndTextElementListener() {
            public void end(String body) {
                currentAssetDescriptor.setDescription(body);
            }
        });
        asset.getChild("thumbnail").setEndTextElementListener(new EndTextElementListener() {
            public void end(String body) {
                currentAssetDescriptor.setThumbnail(body);
            }
        });

        try {
            Xml.parse(this.getInputStream(), Xml.Encoding.UTF_8, root.getContentHandler());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return assetDescriptors;
    }
}
