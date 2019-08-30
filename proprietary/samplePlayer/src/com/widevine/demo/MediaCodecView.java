/*
 * Copyright (C) 2012 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.widevine.demo;

import android.content.Context;
import android.media.AudioFormat;
import android.media.AudioManager;
import android.media.AudioTrack;
import android.media.MediaCodec;
import android.media.MediaCodecInfo;
import android.media.MediaCodecList;
import android.media.MediaCrypto;
import android.media.MediaCryptoException;
import android.media.MediaExtractor;
import android.media.MediaFormat;
import android.net.Uri;
import android.os.Handler;
import android.os.Message;
import android.util.AttributeSet;
import android.util.Log;
import android.view.MotionEvent;
import android.view.SurfaceHolder;
import android.view.SurfaceView;
import android.view.View;
import android.widget.MediaController;

import java.io.IOException;
import java.lang.IllegalStateException;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.UUID;

class CodecState {
    private static final String TAG = "CodecState";

    private MediaCodecView mView;
    private MediaExtractor mExtractor;
    private int mTrackIndex;
    private MediaFormat mFormat;
    private boolean mSawInputEOS, mSawOutputEOS;

    private MediaCodec mCodec;
    private MediaFormat mOutputFormat;
    private ByteBuffer[] mCodecInputBuffers;
    private ByteBuffer[] mCodecOutputBuffers;

    private LinkedList<Integer> mAvailableInputBufferIndices;
    private LinkedList<Integer> mAvailableOutputBufferIndices;
    private LinkedList<MediaCodec.BufferInfo> mAvailableOutputBufferInfos;

    private NonBlockingAudioTrack mAudioTrack;

    private long mLastMediaTimeUs;

    public CodecState(
            MediaCodecView view,
            MediaExtractor extractor,
            int trackIndex,
            MediaFormat format,
            MediaCodec codec) {
        mView = view;
        mExtractor = extractor;
        mTrackIndex = trackIndex;
        mFormat = format;
        mSawInputEOS = mSawOutputEOS = false;

        mCodec = codec;

        mCodec.start();
        mCodecInputBuffers = mCodec.getInputBuffers();
        mCodecOutputBuffers = mCodec.getOutputBuffers();

        mAvailableInputBufferIndices = new LinkedList();
        mAvailableOutputBufferIndices = new LinkedList();
        mAvailableOutputBufferInfos = new LinkedList();

        mLastMediaTimeUs = 0;
    }

    public void release() {
        mCodec.stop();
        mCodecInputBuffers = null;
        mCodecOutputBuffers = null;
        mOutputFormat = null;

        mAvailableOutputBufferInfos = null;
        mAvailableOutputBufferIndices = null;
        mAvailableInputBufferIndices = null;

        mCodec.release();
        mCodec = null;

        if (mAudioTrack != null) {
            mAudioTrack.release();
            mAudioTrack = null;
        }
    }

    public void start() {
        if (mAudioTrack != null) {
            mAudioTrack.play();
        }
    }

    public void pause() {
        if (mAudioTrack != null) {
            mAudioTrack.pause();
        }
    }

    public long getCurrentPositionUs() {
        return mLastMediaTimeUs;
    }

    public void flush() {
        mAvailableInputBufferIndices.clear();
        mAvailableOutputBufferIndices.clear();
        mAvailableOutputBufferInfos.clear();

        mSawInputEOS = false;
        mSawOutputEOS = false;

        if (mAudioTrack != null
                && mAudioTrack.getPlayState() == AudioTrack.PLAYSTATE_STOPPED) {
            mAudioTrack.play();
        }

        mCodec.flush();
    }

    public void doSomeWork() {
        int index = mCodec.dequeueInputBuffer(0 /* timeoutUs */);

        if (index != MediaCodec.INFO_TRY_AGAIN_LATER) {
            mAvailableInputBufferIndices.add(new Integer(index));
        }

        while (feedInputBuffer()) {}

        MediaCodec.BufferInfo info = new MediaCodec.BufferInfo();
        index = mCodec.dequeueOutputBuffer(info, 0 /* timeoutUs */);

        if (index == MediaCodec.INFO_OUTPUT_FORMAT_CHANGED) {
            mOutputFormat = mCodec.getOutputFormat();
            onOutputFormatChanged();
        } else if (index == MediaCodec.INFO_OUTPUT_BUFFERS_CHANGED) {
            mCodecOutputBuffers = mCodec.getOutputBuffers();
        } else if (index != MediaCodec.INFO_TRY_AGAIN_LATER) {
            mAvailableOutputBufferIndices.add(new Integer(index));
            mAvailableOutputBufferInfos.add(info);
        }

        while (drainOutputBuffer()) {}
    }

    /** returns true if more input data could be fed */
    private boolean feedInputBuffer() {
        if (mSawInputEOS || mAvailableInputBufferIndices.isEmpty()) {
            return false;
        }

        int index = mAvailableInputBufferIndices.peekFirst().intValue();

        ByteBuffer codecData = mCodecInputBuffers[index];

        int trackIndex = mExtractor.getSampleTrackIndex();

        if (trackIndex == mTrackIndex) {
            int sampleSize =
                mExtractor.readSampleData(codecData, 0 /* offset */);

            long sampleTime = mExtractor.getSampleTime();

            int sampleFlags = mExtractor.getSampleFlags();

            try {
                if ((sampleFlags & MediaExtractor.SAMPLE_FLAG_ENCRYPTED) != 0) {
                    MediaCodec.CryptoInfo info = new MediaCodec.CryptoInfo();
                    mExtractor.getSampleCryptoInfo(info);

                    mCodec.queueSecureInputBuffer(
                            index, 0 /* offset */, info, sampleTime, 0 /* flags */);
                } else {
                    mCodec.queueInputBuffer(
                            index, 0 /* offset */, sampleSize, sampleTime,
                            0 /* flags */);
                }

                mAvailableInputBufferIndices.removeFirst();
                mExtractor.advance();
            } catch (MediaCodec.CryptoException e) {
                Log.d(TAG, "CryptoException w/ errorCode "
                        + e.getErrorCode() + ", '" + e.getMessage() + "'");
                return false;
            }

            return true;
        } else if (trackIndex < 0) {
            Log.d(TAG, "saw input EOS on track " + mTrackIndex);

            mSawInputEOS = true;

            try {
                mCodec.queueInputBuffer(
                        index, 0 /* offset */, 0 /* sampleSize */,
                        0 /* sampleTime */, MediaCodec.BUFFER_FLAG_END_OF_STREAM);

                mAvailableInputBufferIndices.removeFirst();
            } catch (MediaCodec.CryptoException e) {
                Log.d(TAG, "CryptoException w/ errorCode "
                        + e.getErrorCode() + ", '" + e.getMessage() + "'");
            }
        }

        return false;
    }

    private void onOutputFormatChanged() {
        String mime = mOutputFormat.getString(MediaFormat.KEY_MIME);

        if (mime.startsWith("audio/")) {
            int sampleRate =
                mOutputFormat.getInteger(MediaFormat.KEY_SAMPLE_RATE);

            int channelCount =
                mOutputFormat.getInteger(MediaFormat.KEY_CHANNEL_COUNT);

            mAudioTrack = new NonBlockingAudioTrack(sampleRate, channelCount);
            mAudioTrack.play();
        }
    }

    /** returns true if more output data could be drained */
    private boolean drainOutputBuffer() {
        if (mSawOutputEOS || mAvailableOutputBufferIndices.isEmpty()) {
            return false;
        }

        int index = mAvailableOutputBufferIndices.peekFirst().intValue();
        MediaCodec.BufferInfo info = mAvailableOutputBufferInfos.peekFirst();

        if ((info.flags & MediaCodec.BUFFER_FLAG_END_OF_STREAM) != 0) {
            Log.d(TAG, "saw output EOS on track " + mTrackIndex);

            mSawOutputEOS = true;

            if (mAudioTrack != null) {
                mAudioTrack.stop();
            }
            return false;
        }

        long realTimeUs =
            mView.getRealTimeUsForMediaTime(info.presentationTimeUs);

        long nowUs = mView.getNowUs();

        long lateUs = nowUs - realTimeUs;

        if (mAudioTrack != null) {
            ByteBuffer buffer = mCodecOutputBuffers[index];
            buffer.clear();
            buffer.position(0 /* offset */);

            byte[] audioCopy = new byte[info.size];
            buffer.get(audioCopy, 0, info.size);

            mAudioTrack.write(audioCopy, info.size);

            mCodec.releaseOutputBuffer(index, false /* render */);

            mLastMediaTimeUs = info.presentationTimeUs;

            mAvailableOutputBufferIndices.removeFirst();
            mAvailableOutputBufferInfos.removeFirst();
            return true;
        } else {
            // video
            boolean render;

            if (lateUs < -10000) {
                // too early;
                return false;
            } else if (lateUs > 30000) {
                Log.d(TAG, "video late by " + lateUs + " us.");
                render = false;
            } else {
                render = true;
                mLastMediaTimeUs = info.presentationTimeUs;
            }

            mCodec.releaseOutputBuffer(index, render);

            mAvailableOutputBufferIndices.removeFirst();
            mAvailableOutputBufferInfos.removeFirst();
            return true;
        }
    }

    public long getAudioTimeUs() {
        if (mAudioTrack == null) {
            return 0;
        }

        return mAudioTrack.getAudioTimeUs();
    }
}

class MediaCodecView extends SurfaceView
                     implements MediaController.MediaPlayerControl {
    private static final String TAG = "MediaCodecView";

    private Context mContext;
    private Uri mUri;
    private Map<String, String> mHeaders;
    private boolean mEncrypted;

    private MediaCrypto mCrypto;
    private MediaExtractor mExtractor;

    private Map<Integer, CodecState> mCodecStates;
    CodecState mAudioTrackState;

    private int mState;
    private static final int STATE_IDLE         = 1;
    private static final int STATE_PREPARING    = 2;
    private static final int STATE_PLAYING      = 3;
    private static final int STATE_PAUSED       = 4;

    private Handler mHandler;
    private static final int EVENT_PREPARE            = 1;
    private static final int EVENT_DO_SOME_WORK       = 2;

    private long mDeltaTimeUs;
    private long mDurationUs;

    private MediaController mMediaController;

    public MediaCodecView(Context context) {
        super(context);
        initMediaCodecView();
    }

    public MediaCodecView(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
        initMediaCodecView();
    }

    public MediaCodecView(Context context, AttributeSet attrs, int defStyle) {
        super(context, attrs, defStyle);
        initMediaCodecView();
    }

    private void initMediaCodecView() {
        mState = STATE_IDLE;

        mHandler = new Handler() {
            public void handleMessage(Message msg) {
                switch (msg.what) {
                    case EVENT_PREPARE:
                    {
                        try {
                            prepare();
                            start();
                        } catch (IOException e) {
                            Log.d(TAG, "prepare failed.");
                        } catch (MediaCryptoException e) {
                            Log.d(TAG, "failed to initialize crypto.");
                        }
                        break;
                    }

                    case EVENT_DO_SOME_WORK:
                    {
                        doSomeWork();

                        mHandler.sendMessageDelayed(
                                mHandler.obtainMessage(EVENT_DO_SOME_WORK), 5);
                        break;
                    }

                    default:
                        break;
                }
            }
        };
    }

    public void setDataSource(
            Context context, Uri uri, Map<String, String> headers,
            boolean encrypted) {
        reset();

        mContext = context;
        mUri = uri;
        mHeaders = headers;
        mEncrypted = encrypted;
    }

    private void prepare() throws IOException, MediaCryptoException {
        if (mEncrypted) {
            UUID uuid = new UUID(
                    (long)0xedef8ba979d64aceL, (long)0xa3c827dcd51d21edL);

            try {
                mCrypto = new MediaCrypto(uuid, null);
            } catch (MediaCryptoException e) {
                reset();

                throw e;
            }
        }

        try {
            mExtractor = new MediaExtractor();

            mExtractor.setDataSource(mContext, mUri, mHeaders);
        } catch (IOException e) {
            reset();

            throw e;
        }

        mCodecStates = new HashMap();

        boolean haveAudio = false;
        boolean haveVideo = false;
        for (int i = mExtractor.getTrackCount(); i-- > 0;) {
            MediaFormat format = mExtractor.getTrackFormat(i);
            Log.d(TAG, "track format #" + i + " is " + format);

            String mime = format.getString(MediaFormat.KEY_MIME);

            boolean isVideo = mime.startsWith("video/");
            boolean isAudio = mime.startsWith("audio/");

            if (!haveAudio && isAudio || !haveVideo && isVideo) {
                mExtractor.selectTrack(i);
                addTrack(i, format, mEncrypted);

                if (isAudio) {
                    haveAudio = true;
                } else {
                    haveVideo = true;
                }

                if (format.containsKey(MediaFormat.KEY_DURATION)) {
                    long durationUs = format.getLong(MediaFormat.KEY_DURATION);

                    if (durationUs > mDurationUs) {
                        mDurationUs = durationUs;
                    }
                }

                if (haveAudio && haveVideo) {
                    break;
                }
            }
        }

        mState = STATE_PAUSED;
    }

    private String getSecureDecoderNameForMime(String mime) {
        int n = MediaCodecList.getCodecCount();
        for (int i = 0; i < n; ++i) {
            MediaCodecInfo info = MediaCodecList.getCodecInfoAt(i);

            if (info.isEncoder()) {
                continue;
            }

            String[] supportedTypes = info.getSupportedTypes();

            for (int j = 0; j < supportedTypes.length; ++j) {
                if (supportedTypes[j].equalsIgnoreCase(mime)) {
                    return info.getName() + ".secure";
                }
            }
        }

        return null;
    }

    private void addTrack(
            int trackIndex, MediaFormat format, boolean encrypted) {
        String mime = format.getString(MediaFormat.KEY_MIME);

        boolean isVideo = mime.startsWith("video/");
        boolean isAudio = mime.startsWith("audio/");

        MediaCodec codec;

        if (encrypted && mCrypto.requiresSecureDecoderComponent(mime)) {
            codec = MediaCodec.createByCodecName(
                    getSecureDecoderNameForMime(mime));
        } else {
            codec = MediaCodec.createDecoderByType(mime);
        }

        codec.configure(
                format,
                isVideo ? getHolder().getSurface() : null,
                mCrypto,
                0);

        CodecState state =
            new CodecState(this, mExtractor, trackIndex, format, codec);

        mCodecStates.put(new Integer(trackIndex), state);

        if (isAudio) {
            mAudioTrackState = state;
        }
        // set video view size
        invalidate();
    }

    public void start() {
        Log.d(TAG, "start");

        if (mState == STATE_PLAYING || mState == STATE_PREPARING) {
            return;
        } else if (mState == STATE_IDLE) {
            mState = STATE_PREPARING;
            mHandler.sendMessage(mHandler.obtainMessage(EVENT_PREPARE));
            return;
        } else if (mState != STATE_PAUSED) {
            throw new IllegalStateException();
        }

        for (CodecState state : mCodecStates.values()) {
            state.start();
        }

        mHandler.sendMessage(mHandler.obtainMessage(EVENT_DO_SOME_WORK));

        mDeltaTimeUs = -1;
        mState = STATE_PLAYING;

        if (mMediaController != null) {
            mMediaController.show();
        }
    }

    public void pause() {
        Log.d(TAG, "pause");

        if (mState == STATE_PAUSED) {
            return;
        } else if (mState != STATE_PLAYING) {
            throw new IllegalStateException();
        }

        mHandler.removeMessages(EVENT_DO_SOME_WORK);

        for (CodecState state : mCodecStates.values()) {
            state.pause();
        }

        mState = STATE_PAUSED;
    }

    public void reset() {
        if (mState == STATE_PLAYING) {
            pause();
        }

        if (mMediaController != null) {
            mMediaController.setEnabled(false);
        }

        if (mCodecStates != null) {
            for (CodecState state : mCodecStates.values()) {
                state.release();
            }
            mCodecStates = null;
        }

        if (mExtractor != null) {
            mExtractor.release();
            mExtractor = null;
        }

        if (mCrypto != null) {
            mCrypto.release();
            mCrypto = null;
        }

        mDurationUs = -1;
        mState = STATE_IDLE;
    }

    public void setMediaController(MediaController ctrl) {
        mMediaController = ctrl;
        attachMediaController();
    }

    private void attachMediaController() {
        View anchorView =
            this.getParent() instanceof View ?  (View)this.getParent() : this;

        mMediaController.setMediaPlayer(this);
        mMediaController.setAnchorView(anchorView);
        mMediaController.setEnabled(true);
    }

    private void doSomeWork() {
        for (CodecState state : mCodecStates.values()) {
            state.doSomeWork();
        }
    }

    public long getNowUs() {
        if (mAudioTrackState == null) {
            return System.currentTimeMillis() * 1000;
        }

        return mAudioTrackState.getAudioTimeUs();
    }

    public long getRealTimeUsForMediaTime(long mediaTimeUs) {
        if (mDeltaTimeUs == -1) {
            long nowUs = getNowUs();
            mDeltaTimeUs = nowUs - mediaTimeUs;
        }

        return mDeltaTimeUs + mediaTimeUs;
    }

    public int getDuration() {
        return (int)((mDurationUs + 500) / 1000);
    }

    public int getCurrentPosition() {
        if (mCodecStates == null) {
            return 0;
        }

        long positionUs = 0;

        for (CodecState state : mCodecStates.values()) {
            long trackPositionUs = state.getCurrentPositionUs();

            if (trackPositionUs > positionUs) {
                positionUs = trackPositionUs;
            }
        }

        return (int)((positionUs + 500) / 1000);
    }

    public void seekTo(int timeMs) {
        if (mState != STATE_PLAYING && mState != STATE_PAUSED) {
            return;
        }

        mExtractor.seekTo(timeMs * 1000, MediaExtractor.SEEK_TO_CLOSEST_SYNC);

        for (CodecState state : mCodecStates.values()) {
            state.flush();
        }

        Log.d(TAG, "seek to " + timeMs * 1000);

        mDeltaTimeUs = -1;
    }

    public boolean isPlaying() {
        return mState == STATE_PLAYING;
    }

    public int getBufferPercentage() {
        if (mExtractor == null) {
            return 0;
        }

        long cachedDurationUs = mExtractor.getCachedDuration();

        if (cachedDurationUs < 0 || mDurationUs < 0) {
            return 0;
        }

        int nowMs = getCurrentPosition();

        int percentage =
            100 * (nowMs + (int)(cachedDurationUs / 1000))
                / (int)(mDurationUs / 1000);

        if (percentage > 100) {
            percentage = 100;
        }

        return percentage;
    }

    public boolean canPause() {
        return true;
    }

    public boolean canSeekBackward() {
        return true;
    }

    public boolean canSeekForward() {
        return true;
    }

    @Override
    public int getAudioSessionId() {
        return 0;
    }
 
    private void toggleMediaControlsVisiblity() {
        if (mMediaController.isShowing()) {
            mMediaController.hide();
        } else {
            mMediaController.show();
        }
    }

    @Override
    public boolean onTouchEvent(MotionEvent ev) {
        if (mState != STATE_IDLE && mMediaController != null) {
            toggleMediaControlsVisiblity();
        }
        return false;
    }

    @Override
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int width = 720;
        int height = 480;

        Log.d(TAG, "setting size: " + width + 'x' + height);
        setMeasuredDimension(width, height);
    }

}
