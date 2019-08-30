/*
 * (c)Copyright 2011 Widevine Technologies, Inc
 */

package com.widevine.demo;

import android.app.Activity;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.MediaController;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Button;
import android.view.Display;
import android.view.Gravity;
import android.view.View;
import android.view.WindowManager;
import android.content.Context;

import android.view.SurfaceHolder;
import android.view.SurfaceView;
import android.media.MediaCrypto;
import android.media.MediaExtractor;
import android.media.MediaPlayer;
import android.media.MediaPlayer.OnErrorListener;
import android.media.MediaPlayer.OnCompletionListener;
import android.media.MediaPlayer.OnInfoListener;
import android.util.Log;

import java.io.IOException;

public class VideoPlayerView extends Activity {
    private final static String TAG = "VideoPlayerView";

    private final static float BUTTON_FONT_SIZE = 10;
    private final static String EXIT_FULLSCREEN = "Exit Full Screen";
    private final static String FULLSCREEN = "Enter Full Screen";
    private final static String PLAY = "Play";
    private final static int REFRESH = 1;

    private WidevineDrm drm;
    private FullScreenVideoView videoView;
    private MediaCodecView mediaCodecView;
    private String assetUri;
    private TextView logs;
    private ScrollView scrollView;
    private Context context;
    private ClipImageView bgImage;
    private Button mediaCodecModeButton;
    private Button playButton;
    private Button fullScreen;
    private Handler hRefresh;
    private View contentView;
    private LinearLayout main;
    private LinearLayout sidePanel;
    private boolean enteringFullScreen;
    private boolean useMediaCodec;
    private int width, height;

    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Display display = getWindowManager().getDefaultDisplay();
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);

        height = display.getHeight();
        width = display.getWidth();
        context = this;
        useMediaCodec = false;
        contentView = createView();
        if (drm.isProvisionedDevice()) {
            setContentView(contentView);
        } else {
            setContentView(R.layout.notprovisioned);
        }
        drm.printPluginVersion();
    }

    @Override
    protected void onStop() {
        Log.d(TAG, "onStop.");
        if (videoView != null) {
            if (videoView.isPlaying()) {
                stopPlayback();
            }
        }
        if (mediaCodecView != null) {
            if (mediaCodecView.isPlaying()) {
                stopPlayback();
            }
        }
        super.onStop();
    }

    private View createView() {
        enteringFullScreen = false;
        assetUri = this.getIntent().getStringExtra("com.widevine.demo.Path").replaceAll("wvplay", "http");

        drm = new WidevineDrm(this);
        logMessage("Asset Uri: " + assetUri + "\n");
        logMessage("Drm Server: " + WidevineDrm.Settings.DRM_SERVER_URI + "\n");
        logMessage("Device Id: " + WidevineDrm.Settings.DEVICE_ID + "\n");
        logMessage("Portal Name: " + WidevineDrm.Settings.PORTAL_NAME + "\n");

        // Set log update listener
        WidevineDrm.WidevineDrmLogEventListener drmLogListener =
            new WidevineDrm.WidevineDrmLogEventListener() {

            public void logUpdated() {
                updateLogs();

            }
        };

        logs = new TextView(this);
        drm.setLogListener(drmLogListener);
        drm.registerPortal(WidevineDrm.Settings.PORTAL_NAME);

        scrollView = new ScrollView(this);
        scrollView.addView(logs);

        // Set message handler for log events
        hRefresh = new Handler() {
            @Override
            public void handleMessage(Message msg) {
                switch (msg.what) {
                case REFRESH:
                    /* Refresh UI */
                    logs.setText(drm.logBuffer.toString());
                    scrollView.fullScroll(ScrollView.FOCUS_DOWN);
                    break;
                }
            }
        };

        updateLogs();

        sidePanel = new LinearLayout(this);
        sidePanel.setOrientation(LinearLayout.VERTICAL);

        sidePanel.addView(scrollView, new LinearLayout.LayoutParams(
                (int)(width * 0.35),
                (int)(height * 0.5)));

        LinearLayout.LayoutParams paramsSidePanel = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
        paramsSidePanel.gravity = Gravity.CENTER;
        sidePanel.addView(createButtons(), paramsSidePanel);

        FrameLayout playerFrame = new FrameLayout(this);

        View view;
        if (useMediaCodec) {
            mediaCodecView = new MediaCodecView(this);
            view = mediaCodecView;
        } else {
            videoView = new FullScreenVideoView(this);
            view = videoView;
        }

        playerFrame.addView(view, new FrameLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                FrameLayout.LayoutParams.MATCH_PARENT));

        bgImage = new ClipImageView(this);
        bgImage.setBackgroundDrawable(getResources().getDrawable(R.drawable.play_shield));

        bgImage.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                Log.d(TAG, "Click play (start playback).");
                startPlayback();

            }
        });

        fullScreen = new Button(this);
        fullScreen.setText(FULLSCREEN);

        fullScreen.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                Log.d(TAG, "Click full screen");
                int currentPosition = videoView.getCurrentPosition();
                videoView.setVisibility(View.INVISIBLE);
                if (fullScreen.getText().equals(FULLSCREEN)) {

                    videoView.setFullScreen(true);
                    fullScreen.setText(EXIT_FULLSCREEN);
                    enteringFullScreen = true;
                } else {
                    videoView.setFullScreen(false);
                    fullScreen.setText(FULLSCREEN);
                }
                videoView.setVisibility(View.VISIBLE);

                stopPlayback();
                startPlayback();
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                }
                videoView.seekTo(currentPosition);
            }
        });
        playerFrame.addView(fullScreen, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.WRAP_CONTENT,
                FrameLayout.LayoutParams.WRAP_CONTENT));
        fullScreen.setVisibility(View.INVISIBLE);
        playerFrame.addView(bgImage, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.WRAP_CONTENT,
                FrameLayout.LayoutParams.WRAP_CONTENT));

        main = new LinearLayout(this);
        main.addView(playerFrame, new LinearLayout.LayoutParams((int)(width * 0.65),
                LinearLayout.LayoutParams.FILL_PARENT, 1));
        main.addView(sidePanel, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.FILL_PARENT, 3));

        return main;
    }

    private void startPlayback() {
        logMessage("Playback start.");
        playButton.setText(R.string.stop);
        bgImage.setVisibility(View.GONE);

        if (useMediaCodec) {
            mediaCodecView.setDataSource(
                    this,
                    Uri.parse(assetUri),
                    null /* headers */,
                    true /* encrypted */);

            mediaCodecView.setMediaController(new MediaController(context));
            mediaCodecView.requestFocus();
            mediaCodecView.start();
        } else {
            videoView.setVideoPath(assetUri);
            videoView.setMediaController(new MediaController(context));

            videoView.setOnErrorListener(new OnErrorListener() {
                public boolean onError(MediaPlayer mp, int what, int extra) {
                    String message = "Unknown error: " + what;
                    switch (what) {
                    case MediaPlayer.MEDIA_ERROR_UNKNOWN:
                        message = "Unable to play media";
                        break;
                    case MediaPlayer.MEDIA_ERROR_SERVER_DIED:
                        message = "Server failed";
                        break;
                    case MediaPlayer.MEDIA_ERROR_NOT_VALID_FOR_PROGRESSIVE_PLAYBACK:
                        message = "Invalid media";
                        break;
                    }
                    logMessage(message + "\n");

                    updateLogs();
                    bgImage.setVisibility(View.VISIBLE);
                    return false;
                }
            });

            videoView.setOnCompletionListener(new OnCompletionListener() {
                public void onCompletion(MediaPlayer mp) {
                    Log.d(TAG, "onCompletion.");
                    stopPlayback();
                }
            });

            videoView.setOnInfoListener(new OnInfoListener() {
                public boolean onInfo(MediaPlayer mp, int what, int extra) {

                    String message = "Unknown info message";
                    switch (what) {
                    case MediaPlayer.MEDIA_INFO_UNKNOWN:
                        message = "Unknown info message 2";
                        break;
                    case MediaPlayer.MEDIA_INFO_VIDEO_RENDERING_START:
                        message = "Video rendering start";
                        break;
                    case MediaPlayer.MEDIA_INFO_VIDEO_TRACK_LAGGING:
                        message = "Video track lagging";
                        break;
                    case MediaPlayer.MEDIA_INFO_BUFFERING_START:
                        message = "Buffering start";
                        break;
                    case MediaPlayer.MEDIA_INFO_BUFFERING_END:
                        message = "Buffering end";
                        break;
                    /*** TODO: Below needs to be added to MediaPlayer.java. Hard coded for now --Zan
                    case MediaPlayer.MEDIA_INFO_NETWORK_BANDWIDTH: ***/
                    case 703:
                        message = "Network bandwidth";
                        break;
                    case MediaPlayer.MEDIA_INFO_BAD_INTERLEAVING:
                        message = "Bad interleaving";
                        break;
                    case MediaPlayer.MEDIA_INFO_NOT_SEEKABLE:
                        message = "Not seekable";
                        break;
                    case MediaPlayer.MEDIA_INFO_METADATA_UPDATE:
                        message = "Metadata update";
                        break;
                    }
                    logMessage(message + "\n");

                    updateLogs();

                    return true;
                }
            });

            videoView.requestFocus();

            videoView.start();

            if (videoView.getFullScreen()) {
                sidePanel.setVisibility(View.GONE);
            } else {
                sidePanel.setVisibility(View.VISIBLE);
            }

            fullScreen.setVisibility(View.VISIBLE);
            videoView.setFullScreenDimensions(contentView.getRight() - contentView.getLeft(),
                    contentView.getBottom() - contentView.getTop());
        }
    }

    private void stopPlayback() {
        logMessage("Stop Playback.");
        playButton.setText(R.string.play);
        bgImage.setVisibility(View.VISIBLE);

        if (useMediaCodec) {
            mediaCodecView.reset();
        } else {
            videoView.stopPlayback();

            fullScreen.setVisibility(View.INVISIBLE);
            if (videoView.getFullScreen() && !enteringFullScreen) {
                videoView.setVisibility(View.INVISIBLE);
                videoView.setFullScreen(false);
                videoView.setVisibility(View.VISIBLE);
                sidePanel.setVisibility(View.VISIBLE);
                fullScreen.setText(FULLSCREEN);
            }
        }
        enteringFullScreen = false;
    }

    private View createButtons() {
        mediaCodecModeButton = new Button(this);
        if (useMediaCodec) {
            mediaCodecModeButton.setText(R.string.normal_mode);
        } else {
            mediaCodecModeButton.setText(R.string.mediacodec_mode);
        }
        mediaCodecModeButton.setTextSize(BUTTON_FONT_SIZE);

        mediaCodecModeButton.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                onStop();

                useMediaCodec = (useMediaCodec) ? false : true;
                Log.d(TAG, "Click media codec mode.  useMediaCodec = "+useMediaCodec);
                contentView = createView();
                if (drm.isProvisionedDevice()) {
                    setContentView(contentView);
                } else {
                    setContentView(R.layout.notprovisioned);
                }
            }
        });

        playButton = new Button(this);
        playButton.setText(R.string.play);
        playButton.setTextSize(BUTTON_FONT_SIZE);

        playButton.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                Log.d(TAG, "Click play");
                Button b = (Button) v;
                if (b.getText().equals(PLAY)) {
                    startPlayback();
                } else {
                    stopPlayback();
                }
            }
        });

        Button rightsButton = new Button(this);
        rightsButton.setText(R.string.acquire_rights);
        rightsButton.setTextSize(BUTTON_FONT_SIZE);

        rightsButton.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                Log.d(TAG, "Click rights");
                drm.acquireRights(assetUri);
                updateLogs();
            }
        });

        Button removeButton = new Button(this);
        removeButton.setText(R.string.remove_rights);
        removeButton.setTextSize(BUTTON_FONT_SIZE);

        removeButton.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                Log.d(TAG, "Click remove rights");
                drm.removeRights(assetUri);
                updateLogs();
            }
        });

        Button checkButton = new Button(this);
        checkButton.setText(R.string.show_rights);
        checkButton.setTextSize(BUTTON_FONT_SIZE);

        checkButton.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                Log.d(TAG, "Click check rights");
                drm.showRights(assetUri);
                updateLogs();
            }
        });

        Button checkConstraints = new Button(this);
        checkConstraints.setText(R.string.constraints);
        checkConstraints.setTextSize(BUTTON_FONT_SIZE);

        checkConstraints.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                Log.d(TAG, "Click get constraints");
                drm.getConstraints(assetUri);
                updateLogs();

            }
        });

        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.FILL_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT, 1);

        params.setMargins(0, 0, 0, 5);
        LinearLayout buttonsLeft = new LinearLayout(this);

        buttonsLeft.setOrientation(LinearLayout.VERTICAL);
        buttonsLeft.addView(playButton, params);
        buttonsLeft.addView(rightsButton, params);
        buttonsLeft.addView(checkConstraints, params);

        LinearLayout buttonsRight = new LinearLayout(this);
        buttonsRight.addView(mediaCodecModeButton, params);
        buttonsRight.setOrientation(LinearLayout.VERTICAL);
        buttonsRight.addView(checkButton, params);
        buttonsRight.addView(removeButton, params);

        LinearLayout.LayoutParams paramsSides = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.FILL_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT, 1);
        paramsSides.gravity = Gravity.BOTTOM;

        LinearLayout buttons = new LinearLayout(this);
        buttons.addView(buttonsLeft, paramsSides);
        buttons.addView(buttonsRight, paramsSides);

        return buttons;
    }

    private void updateLogs() {
        hRefresh.sendEmptyMessage(REFRESH);
    }

    @Override
    protected void onPause() {
        Log.v("VideoPlayerView", "------------------- onPause ----------------");
        onStop();
    }

    private void logMessage(String message) {
        Log.d(TAG, message);
        drm.logBuffer.append(message);
    }

}
