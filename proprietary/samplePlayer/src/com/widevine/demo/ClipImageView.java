/*
 * (c)Copyright 2011 Widevine Technologies, Inc
 */

package com.widevine.demo;

import android.widget.ImageView;
import android.view.MotionEvent;
import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Canvas;
import android.graphics.Rect;

public class ClipImageView extends ImageView {

    private boolean touchedDown;
    private float touchX, touchY, radius;
    private boolean radiusInc;

    private Bitmap selectCircle;

    public ClipImageView(Context ctxt) {
        super(ctxt);

        touchedDown = false;

        BitmapFactory.Options options = new BitmapFactory.Options();
        options.inDither = true;
        selectCircle = BitmapFactory.decodeResource(getResources(), R.drawable.selection_circle,
                options);
    }

    @Override
    public boolean onTouchEvent(MotionEvent e) {

        if (e.getAction() == MotionEvent.ACTION_DOWN) {
            touchX = e.getX();
            touchY = e.getY();
            radius = 60;
            radiusInc = false;
            touchedDown = true;

        } else if (e.getAction() == MotionEvent.ACTION_UP) {
            touchedDown = false;

        }
        // return true;
        return super.onTouchEvent(e);
    }

    @Override
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        if (touchedDown) {
            canvas.drawBitmap(selectCircle, null, new Rect((int) (touchX - radius),
                    (int) (touchY - radius), (int) (touchX + radius),
                    (int) (touchY + radius)), null);
            if (radiusInc) {
                radius += 5;
            }
            else {
                radius -= 5;
            }
            if (radius >= 60 || radius <= 0) {
                radiusInc = !radiusInc;
            }
        }

        invalidate();
    }
}
