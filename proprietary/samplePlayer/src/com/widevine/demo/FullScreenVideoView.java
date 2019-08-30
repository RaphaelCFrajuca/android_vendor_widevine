/*
 * (c)Copyright 2011 Widevine Technologies, Inc
 */

package com.widevine.demo;

import android.content.Context;
import android.widget.VideoView;

public class FullScreenVideoView extends VideoView {

    private boolean fullscreen;
    private int rLeft, rRight, rTop, rBottom, regularHeight, regularWidth;
    private int fullScreenWidth, fullScreenHeight;

    public FullScreenVideoView(Context context) {
        super(context);
        fullscreen = false;
        regularHeight = 0;
        regularWidth = 0;
        rBottom = 0;
        rRight = 0;
        rTop = 0;
        rLeft = 0;
        fullScreenWidth = 1280;
        fullScreenHeight = 800;
    }

    public void setFullScreenDimensions(int width, int height) {
        fullScreenWidth = width;
        fullScreenHeight = height;
    }

    public void setFullScreen(boolean fullscreen) {
        this.fullscreen = fullscreen;
        this.requestLayout();
    }

    public boolean getFullScreen() {
        return this.fullscreen;
    }

    @Override
    protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
        if (rLeft == 0 && rRight == 0 && rTop == 0 && rBottom == 0) {
            rBottom = bottom;
            rRight = right;
            rTop = top;
            rLeft = left;
        }
        if (fullscreen) {
            super.onLayout(true, left, top, fullScreenWidth, fullScreenHeight);
        } else {
            if (rLeft == 0 && rRight == 0 && rTop == 0 && rBottom == 0) {
                super.onLayout(changed, left, top, right, bottom);
            } else {
                super.onLayout(changed, rLeft, rTop, rRight, rBottom);
            }
        }
    }

    @Override
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        if (regularHeight == 0 && regularWidth == 0) {
            regularHeight = heightMeasureSpec;
            regularWidth = widthMeasureSpec;
        }
        if (fullscreen) {
            this.setMeasuredDimension(fullScreenWidth, fullScreenHeight);
        } else {
            if (regularHeight == 0 && regularWidth == 0) {
                super.onMeasure(widthMeasureSpec, heightMeasureSpec);
            } else {
                super.onMeasure(regularWidth, regularHeight);
            }
        }
    }

}
