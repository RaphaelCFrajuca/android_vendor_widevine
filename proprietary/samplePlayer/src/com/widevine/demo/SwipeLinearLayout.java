/*
 * (c)Copyright 2011 Widevine Technologies, Inc
 */

package com.widevine.demo;

import android.content.Context;
import android.view.MotionEvent;
import android.view.View;
import android.widget.LinearLayout;

public class SwipeLinearLayout extends LinearLayout {
    private View.OnClickListener prev;
    private View.OnClickListener next;

    float startX, startY, endX, endY;

    public SwipeLinearLayout(Context c) {
        super(c);
    }

    public void setNext(View.OnClickListener next) {
        this.next = next;
    }

    public void setPrev(View.OnClickListener prev) {
        this.prev = prev;
    }

    public boolean onTouchEvent(MotionEvent e) {
        if (e.getAction() == MotionEvent.ACTION_DOWN) {
            startX = e.getX();
            startY = e.getY();
            return true;
        } else if (e.getAction() == MotionEvent.ACTION_UP) {
            endX = e.getX();
            endY = e.getY();

            if (Math.abs(startY - endY) < 75) {
                if ((startX - endX) > 200.0) {
                    // go forward
                    if (next != null) {
                        next.onClick(null);
                    }
                } else if ((startX - endX) < -200.0) {
                    // go back
                    if (prev != null) {
                        prev.onClick(null);
                    }
                }
                startX = startY = endX = endY = 0;
            }
            return true;
        }
        return false;
    }

}
