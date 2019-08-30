/*
 * (c)Copyright 2011 Widevine Technologies, Inc
 */

package com.widevine.demo;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.ArrayList;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.util.Log;

import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Button;

public abstract class AssetActivity extends Activity {

    public static final String TAG = "WVM Sample Player";

    private int currentPage;
    protected ArrayList<AssetsPage> pages;
    private Context context;

    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        context = this;

        initialize();
    }

    protected void initialize() {
        currentPage = 0;

        pages = new ArrayList<AssetsPage>();

        if (setUpAssetPages()) {
            setContentView(createView(this));
        } else {
            setContentView(R.layout.empty);
        }
    }

    protected abstract boolean setUpAssetPages();

    private View createView(Context ctxt) {

        ImageView empty = new ImageView(this);
        empty.setBackgroundDrawable(getResources().getDrawable(R.drawable.empty));

        View[] clips = new View[6];
        BitmapFactory.Options options = new BitmapFactory.Options();
        options.inDither = true;

        AssetsPage page = pages.get(currentPage);

        for (int i = 0; i < page.getPageCount(); i++) {

            AssetItem assetItem = page.getPage(i);
            clips[i] = createViewItem(getBitmapFromAssetItem(assetItem), assetItem.getAssetPath(),
                    assetItem.getTitle());

        }

        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.FILL_PARENT, 1);
        params.gravity = Gravity.CENTER_HORIZONTAL | Gravity.TOP;

        LinearLayout.LayoutParams paramsMain = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.FILL_PARENT, 1);
        paramsMain.gravity = Gravity.CENTER;

        LinearLayout left = new LinearLayout(ctxt);
        left.setOrientation(LinearLayout.VERTICAL);
        if (clips[0] != null) {
            left.addView(clips[0], params);
        }
        if (clips[3] != null) {
            left.addView(clips[3], params);
        } else {
            left.addView(createEmptyView(), params);
        }

        LinearLayout middle = new LinearLayout(ctxt);
        middle.setOrientation(LinearLayout.VERTICAL);
        if (clips[1] != null) {
            middle.addView(clips[1], params);
        }
        if (clips[4] != null) {
            middle.addView(clips[4], params);
        } else {
            middle.addView(createEmptyView(), params);
        }

        LinearLayout right = new LinearLayout(ctxt);
        right.setOrientation(LinearLayout.VERTICAL);
        if (clips[2] != null) {
            right.addView(clips[2], params);
        }
        params.gravity = Gravity.BOTTOM;
        if (clips[5] != null) {
            right.addView(clips[5], params);
        } else {
            right.addView(createEmptyView(), params);
        }
        params.gravity = Gravity.CENTER_HORIZONTAL | Gravity.TOP;

        LinearLayout body = new LinearLayout(ctxt);

        body.addView(left, paramsMain);
        body.addView(middle, paramsMain);
        body.addView(right, paramsMain);

        // Next button listener
        View.OnClickListener nextButtonListener = new View.OnClickListener() {

            public void onClick(View v) {
                currentPage++;
                Log.d(TAG, "Click next page: " + currentPage);
                if (currentPage >= pages.size()) {
                    currentPage = 0;
                }
                setContentView(createView(context));
            }
        };

        Button next = new Button(this);
        next.setText(">>");
        next.setTextSize(10);
        next.setOnClickListener(nextButtonListener);

        // Previous button listener
        View.OnClickListener prevButtonListener = new View.OnClickListener() {

            public void onClick(View v) {

                currentPage--;
                Log.d(TAG, "Click prev page: " + currentPage);
                if (currentPage < 0) {
                    currentPage = pages.size() - 1;
                }
                setContentView(createView(context));

            }
        };
        Button prev = new Button(this);
        prev.setText("<<");
        prev.setTextSize(10);
        prev.setOnClickListener(prevButtonListener);

        LinearLayout buttons = new LinearLayout(this);
        buttons.addView(prev, params);
        buttons.addView(next, params);

        body.setBackgroundDrawable(this.getResources().getDrawable(R.drawable.background3));

        SwipeLinearLayout main = new SwipeLinearLayout(this);
        main.setNext(nextButtonListener);
        main.setPrev(prevButtonListener);
        main.setOrientation(LinearLayout.VERTICAL);
        main.addView(body, params);

        LinearLayout.LayoutParams paramButtons = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
        paramButtons.gravity = Gravity.CENTER;

        main.addView(buttons, paramButtons);
        return main;
    }

    private View createEmptyView() {
        ImageView empty = new ImageView(this);
        empty.setBackgroundDrawable(getResources().getDrawable(R.drawable.empty));

        TextView emptyText = new TextView(this);

        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT, 1);
        params.gravity = Gravity.CENTER_HORIZONTAL | Gravity.TOP;
        LinearLayout body = new LinearLayout(this);

        body.setOrientation(LinearLayout.VERTICAL);
        body.addView(empty, params);

        body.addView(emptyText, params);

        return body;
    }

    private View createViewItem(Bitmap image, String path, String title) {

        final String assetPath = path;

        ClipImageView clip = new ClipImageView(this);

        clip.setImageBitmap(image);

        // Set the onClick listener for each image
        clip.setOnClickListener(new View.OnClickListener() {

            public void onClick(View v) {
                Log.d(TAG, "Click Asset path: " + assetPath);
                Intent intent = new Intent(context, VideoPlayerView.class);
                intent.putExtra("com.widevine.demo.Path", assetPath);
                context.startActivity(intent);

            }
        });

        TextView text = new TextView(this);
        text.setText((title == null) ? path : title);

        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT, 1);
        params.gravity = Gravity.CENTER;
        LinearLayout body = new LinearLayout(this);

        body.setOrientation(LinearLayout.VERTICAL);
        body.addView(clip, params);

        body.addView(text, params);

        return body;

    }

    private Bitmap getBitmapFromAssetItem(AssetItem assetItem) {
        Bitmap clipImage = null;
        String imageUrl = null;

        if (assetItem.getImagePath() == null || assetItem.getImagePath().equals("")) {
            if (!assetItem.getAssetPath().contains("http") && !assetItem.getAssetPath().contains("wvplay"))
                clipImage = BitmapFactory.decodeResource(getResources(), R.drawable.download_clip);
            else
                clipImage = BitmapFactory.decodeResource(getResources(), R.drawable.streaming_clip);
        } else {
            InputStream bitmapStream = null;
            if (assetItem.getImagePath().contains("http")) {

                imageUrl = assetItem.getImagePath();
                if (imageUrl != null) {
                    ImageHandler imageHandler = new ImageHandler(imageUrl);
                    imageHandler.start();
                    try {
                        imageHandler.join();
                    } catch (InterruptedException e) {
                    }

                    clipImage = imageHandler.getBitmap();
                }

            } else {
                try {
                    bitmapStream = new FileInputStream(assetItem.getImagePath());
                } catch (FileNotFoundException e) {
                    bitmapStream = null;
                }

                clipImage = BitmapFactory.decodeStream(bitmapStream);
            }

            if (clipImage == null) {
                clipImage = BitmapFactory.decodeResource(getResources(), R.drawable.streaming_clip);
            }

        }

        return clipImage;
    }

}
