/*
 * (c)Copyright 2011 Widevine Technologies, Inc
 */

package com.widevine.demo;

import java.io.File;
import java.io.FilenameFilter;
import java.util.ArrayList;

public class DownloadActivity extends AssetActivity {

    protected boolean setUpAssetPages() {
        pages = new ArrayList<AssetsPage>();

        File[] assets = getDownloadedClips();

        if (assets != null && assets.length > 0) {
            for (int i = 0; i < assets.length;) {
                AssetsPage page = new AssetsPage();
                for (int j = 0; j < AssetsPage.MAX_ITEMS && i < assets.length; j++, i++) {
                    page.addPage(assets[i].getAbsolutePath(), null, null);
                }
                pages.add(page);
            }
            return true;
        } else {
            return false;
        }
    }

    private File[] getDownloadedClips() {

        File file = new File("/sdcard/Widevine");

        FilenameFilter filter = new FilenameFilter() {
            public boolean accept(File dir, String name) {
                File file = new File(dir.getAbsolutePath() + File.separator + name);
                if (!file.isDirectory()
                        && !name.equals("curl")
                    && (name.contains(".wvm") || name.contains(".ts") || name.contains(".mp4") ||
                        name.contains(".m3u8") | !name.contains(".")))
                    return true;
                else
                    return false;
            }
        };

        return file.listFiles(filter);

    }

}
