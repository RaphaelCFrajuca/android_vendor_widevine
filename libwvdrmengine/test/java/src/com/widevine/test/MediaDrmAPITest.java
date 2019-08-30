/*
 * (c)Copyright 2011 Widevine Technologies, Inc
 */

package com.widevine.test;

import android.app.Activity;
import android.os.Bundle;
import android.os.Looper;
import android.view.View;
import android.view.SurfaceView;
import android.view.SurfaceHolder;
import android.view.Surface;
import android.content.Context;
import android.media.MediaDrm;
import android.media.MediaDrm.CryptoSession;
import android.media.MediaDrmException;
import android.media.NotProvisionedException;
import android.media.MediaCrypto;
import android.media.MediaCodec;
import android.media.MediaCryptoException;
import android.media.MediaCodec.CryptoException;
import android.media.MediaCodecList;
import android.media.MediaCodec.CryptoInfo;
import android.media.MediaCodecInfo;
import android.media.MediaFormat;
import android.util.Log;
import android.util.AttributeSet;
import java.util.UUID;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.ListIterator;
import java.util.Iterator;
import java.util.HashMap;
import java.util.Random;
import java.nio.ByteBuffer;
import java.lang.Exception;
import java.lang.InterruptedException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

class SurfacePanel extends SurfaceView implements SurfaceHolder.Callback
{
    private final String TAG = "SurfacePanel";

    public SurfacePanel(Context context, AttributeSet attrSet)
    {
        super(context, attrSet);
        SurfaceHolder holder = getHolder();
        holder.addCallback(this);
    }

    @Override
    public void surfaceDestroyed(SurfaceHolder holder)
    {
        Log.d(TAG, "surfaceDestroyed");
    }

    @Override
    public void surfaceChanged(SurfaceHolder holder, int format, int width,
                               int height)
    {
        Log.d(TAG, "surfaceChanged");
    }

    @Override
    public void surfaceCreated(SurfaceHolder holder)
    {
        Log.d(TAG, "surfaceCreated");
    }
}

public class MediaDrmAPITest extends Activity {
    private final String TAG = "MediaDrmAPITest";

    static final String kKeyServerUrl = "https://jmt17.google.com/video-dev/license/GetCencLicense";
    static final String kOperatorSessionKeyServerUrl = "http://kir03wwwg185.widevine.net/drm";

    static final UUID kWidevineScheme = new UUID(0xEDEF8BA979D64ACEL, 0xA3C827DCD51D21EDL);

    private boolean mTestFailed;

    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);

        new Thread() {
            @Override
            public void run() {
                mTestFailed = false;

                testWidevineSchemeSupported();
                testProperties();
                testQueryKeyStatus();
                testClearContentNoKeys();
                testEncryptedContent();
                testGenericEncryptAndDecrypt();
                testGenericSign();
                testGenericVerify();
                testGenericMultipleKeys();

                if (mTestFailed) {
                    Log.e(TAG, "TEST FAILED!");
                } else {
                    Log.e(TAG, "TEST SUCCESS!");
                }
            }
        }.start();
    }

    private MediaDrm mDrm;
    private Looper mLooper;
    private Object mLock = new Object();

    private MediaDrm startDrm() {

        new Thread() {
            @Override
            public void run() {
                // Set up a looper to handle events
                Looper.prepare();

                // Save the looper so that we can terminate this thread
                // after we are done with it.
                mLooper = Looper.myLooper();

                try {
                    mDrm = new MediaDrm(kWidevineScheme);
                } catch (MediaDrmException e) {
                    Log.e(TAG, "Failed to create MediaDrm: " + e.getMessage());
                    e.printStackTrace();
                    mTestFailed = true;
                    return;
                }

                synchronized(mLock) {

                    mDrm.setOnEventListener(new MediaDrm.OnEventListener() {
                            @Override
                            public void onEvent(MediaDrm md, byte[] sessionId, int event,
                                                int extra, byte[] data) {
                                if (event == MediaDrm.EVENT_PROVISION_REQUIRED) {
                                    Log.i(TAG, "Provisioning is required");
                                } else if (event == MediaDrm.EVENT_KEY_REQUIRED) {
                                    Log.i(TAG, "MediaDrm event: Key required");
                                } else if (event == MediaDrm.EVENT_KEY_EXPIRED) {
                                    Log.i(TAG, "MediaDrm event: Key expired");
                                } else if (event == MediaDrm.EVENT_VENDOR_DEFINED) {
                                    Log.i(TAG, "MediaDrm event: Vendor defined: " + event);
                                }
                            }
                        });
                    mLock.notify();
                }

                Looper.loop();  // Blocks forever until Looper.quit() is called.
            }
        }.start();

        // wait for mDrm to be created
        synchronized(mLock) {
            try {
                mLock.wait(1000);
            } catch (Exception e) {
            }
        }

        if (mDrm == null) {
            Log.e(TAG, "Failed to create drm");
        }

        return mDrm;
    }

    private void stopDrm(MediaDrm drm) {
        if (drm != mDrm) {
            Log.e(TAG, "invalid drm specified in stopDrm");
            mTestFailed = true;
        }
        mLooper.quit();
    }

    private byte[] openSession(MediaDrm drm) {
        byte[] sessionId = null;
        boolean retryOpen;
        do {
            try {
                retryOpen = false;
                sessionId = drm.openSession();
            } catch (NotProvisionedException e) {
                Log.i(TAG, "Missing certificate, provisioning");
                ProvisionRequester provisionRequester = new ProvisionRequester();
                provisionRequester.doTransact(drm);
                retryOpen = true;
            }
        } while (retryOpen);
        return sessionId;
    }

    private void testWidevineSchemeSupported() {
        if (!MediaDrm.isCryptoSchemeSupported(kWidevineScheme)) {
            Log.e(TAG, "testWidevineSchemeSupported failed");
            mTestFailed = true;
            finish();
        }
    }

    private void testProperties() {
        MediaDrm drm = startDrm();
        Log.i(TAG, "vendor: " + drm.getPropertyString(MediaDrm.PROPERTY_VENDOR));
        Log.i(TAG, "version: " + drm.getPropertyString(MediaDrm.PROPERTY_VERSION));
        Log.i(TAG, "description: " + drm.getPropertyString(MediaDrm.PROPERTY_DESCRIPTION));
        Log.i(TAG, "deviceId: " + Arrays.toString(drm.getPropertyByteArray(MediaDrm.PROPERTY_DEVICE_UNIQUE_ID)));
        Log.i(TAG, "algorithms: " + drm.getPropertyString(MediaDrm.PROPERTY_ALGORITHMS));

        // widevine-specific properties
        Log.i(TAG, "security level: " + drm.getPropertyString("securityLevel"));
        Log.i(TAG, "system ID: " + drm.getPropertyString("systemId"));
        stopDrm(drm);
    }

    private void testQueryKeyStatus() {
        MediaDrm drm = startDrm();
        byte[] sessionId = openSession(drm);
        getKeys(drm, sessionId);

        Log.i(TAG, "Query Key Status:");
        HashMap<String, String> keyStatus = drm.queryKeyStatus(sessionId);
        Iterator<String> iterator = keyStatus.keySet().iterator();
        while (iterator.hasNext()) {
            String name = iterator.next();
            Log.i(TAG, "\t" + name + " = " + keyStatus.get(name));
        }

        drm.closeSession(sessionId);
        stopDrm(drm);
    }

    private void getKeys(MediaDrm drm, byte[] sessionId) {
        final byte[] kPssh = hex2ba("08011210e02562e04cd55351b14b3d748d36ed8e");
        final String kClientAuth = "?source=YOUTUBE&video_id=EGHC6OHNbOo&oauth=ya.gtsqawidevine";
        final String kPort = "80";
        KeyRequester keyRequester = new KeyRequester(kPssh, kKeyServerUrl + ":" + kPort + kClientAuth);
        keyRequester.doTransact(drm, sessionId);
    }

    private void testEncryptedContent() {
        MediaDrm drm = startDrm();
        byte[] sessionId = openSession(drm);
        getKeys(drm, sessionId);
        testDecrypt(sessionId);
        drm.closeSession(sessionId);
        stopDrm(drm);
    }

    private void testGenericEncryptAndDecrypt() {
        final byte[] kOperatorSessionAESPssh = hex2ba("080112103be2b25db355fc64a0e69a50f4dbb298");

        MediaDrm drm = startDrm();
        byte[] sessionId = openSession(drm);

        KeyRequester keyRequester = new KeyRequester(kOperatorSessionAESPssh, kOperatorSessionKeyServerUrl);
        keyRequester.doTransact(drm, sessionId);

        CryptoSession cs = drm.getCryptoSession(sessionId, "AES/CBC/NoPadding", "HmacSHA256");

        // operator_session_key_permissions=allow_encrypt | allow_decrypt
        byte[] aes_key_id = hex2ba("3be2b25db355fc64a0e69a50f4dbb298");
        byte[] aes_key = hex2ba("5762d22a5e17d5402dc310a7c33ce539");

        byte[] clr_data = hex2ba("4c02bcc3943aa828ecf7bbb16420572d00cabb21c3084c422217fee7fadd766d" +
                                 "4bf726a232d029a81830e40e1e12ba34ba005ca6ce8033a0e3602a52b9b8d3d4" +
                                 "b15dc458730f8affebbf35b1536c1a5d42370cf93c5b4094c0920bb1b2333f6a" +
                                 "1897c5dd62eadfc1060786b0f69f228d5d7241cc644b85c35b9a7f4b893b5b85");
        byte[] enc_data = hex2ba("ee92d402f55f1d7eef4844803d9d43a603a4dd13f4a2ad5ea7653adcefa74b06" +
                                 "ff459ab476a497567198c7cfa06d6fdd66b7924c2ca430baf534c5e00c800a06" +
                                 "d0c108057ceab2ea33671d83e35eaaf1f1ff0f7e1618d05810a47b12cbc0806f" +
                                 "d6ba8127a5e411f49b4e1790b1a6cb963e33d6cbc6569c44b4e1b28005fd1dde");

        byte[] iv = hex2ba("3ec0f3d3970fbd541ac4e7e1d06a6131");

        byte[] result = cs.decrypt(aes_key_id, enc_data, iv);
        if (Arrays.equals(clr_data, result)) {
            Log.d(TAG, "Decrypt test passed!");
        } else {
            Log.d(TAG, "Decrypt test failed!");
            mTestFailed = true;
        }

        result = cs.encrypt(aes_key_id, clr_data, iv);
        if (Arrays.equals(enc_data, result)) {
            Log.d(TAG, "Encrypt test passed!");
        } else {
            Log.d(TAG, "Encrypt test failed!");
            mTestFailed = true;
        }
        drm.closeSession(sessionId);
        stopDrm(drm);
    }

    private void testGenericSign() {
        final byte[] kOperatorSessionSignPssh = hex2ba("080112102685086ee9cb5835b063ab20786ffd78");

        MediaDrm drm = startDrm();
        byte[] sessionId = openSession(drm);
        KeyRequester keyRequester = new KeyRequester(kOperatorSessionSignPssh, kOperatorSessionKeyServerUrl);
        keyRequester.doTransact(drm, sessionId);

        CryptoSession cs = drm.getCryptoSession(sessionId, "AES/CBC/NoPadding", "HmacSHA256");

        // operator_session_key_permissions=allow_sign
        byte[] signing_key_id = hex2ba("2685086ee9cb5835b063ab20786ffd78");
        byte[] signing_key = hex2ba("b3dddf87d1cfc0b04c9253231ff89b9e374ef2f424edc7b7f4b2c10e39768ee8");

        byte[] data = hex2ba("4c02bcc3943aa828ecf7bbb16420572d00cabb21c3084c422217fee7fadd766d" +
                             "4bf726a232d029a81830e40e1e12ba34ba005ca6ce8033a0e3602a52b9b8d3d4" +
                             "b15dc458730f8affebbf35b1536c1a5d42370cf93c5b4094c0920bb1b2333f6a" +
                             "1897c5dd62eadfc1060786b0f69f228d5d7241cc644b85c35b9a7f4b893b5b85");

        byte[] hmacsha256 = hex2ba("5fc29a4c15fcf9e1e26b63b3be169d7f53e61e1564b92876f70c9ffd17697437");

        byte[] result = cs.sign(signing_key_id, data);
        if (Arrays.equals(hmacsha256, result)) {
            Log.d(TAG, "Signing test passed!");
        } else {
            Log.d(TAG, "Signing test failed!");
            mTestFailed = true;
        }
        drm.closeSession(sessionId);
        stopDrm(drm);
    }

    private void testGenericVerify() {
        MediaDrm drm = startDrm();
        byte[] sessionId = openSession(drm);
        final byte[] kOperatorSessionVerifyPssh = hex2ba("0801121097c003f73b1a53aa51ba54a6ef631ca0");

        KeyRequester keyRequester = new KeyRequester(kOperatorSessionVerifyPssh, kOperatorSessionKeyServerUrl);
        keyRequester.doTransact(drm, sessionId);

        CryptoSession cs = drm.getCryptoSession(sessionId, "AES/CBC/NoPadding", "HmacSHA256");

        // operator_session_key_permissions=allow_signature_verify
        byte[] verify_key_id = hex2ba("97c003f73b1a53aa51ba54a6ef631ca0");
        byte[] verify_key = hex2ba("cfe2acb04ad5169153690c1932d5d2c6062a4607d274901e935d27b77ad48b2e");

        byte[] data = hex2ba("4c02bcc3943aa828ecf7bbb16420572d00cabb21c3084c422217fee7fadd766d" +
                             "4bf726a232d029a81830e40e1e12ba34ba005ca6ce8033a0e3602a52b9b8d3d4" +
                             "b15dc458730f8affebbf35b1536c1a5d42370cf93c5b4094c0920bb1b2333f6a" +
                             "1897c5dd62eadfc1060786b0f69f228d5d7241cc644b85c35b9a7f4b893b5b85");

        byte[] hmacsha256 = hex2ba("6bd61722e5cc3e698d536317309940328ab973be3a3b5705650aa09a48ebbf61");

        if (cs.verify(verify_key_id, data, hmacsha256)) {
            Log.d(TAG, "Verify test passed!");
        } else {
            Log.d(TAG, "Verify test failed!");
            mTestFailed = true;
        }
        drm.closeSession(sessionId);
        stopDrm(drm);
    }

    private void testGenericMultipleKeys() {
        final byte[] kOperatorSessionAESPssh = hex2ba("080112303be2b25db355fc64a0e69a50f4dbb2982685086ee9cb" +
                                                      "5835b063ab20786ffd7897c003f73b1a53aa51ba54a6ef631ca0");

        MediaDrm drm = startDrm();
        byte[] sessionId = openSession(drm);

        KeyRequester keyRequester = new KeyRequester(kOperatorSessionAESPssh, kOperatorSessionKeyServerUrl);
        keyRequester.doTransact(drm, sessionId);

        CryptoSession cs = drm.getCryptoSession(sessionId, "AES/CBC/NoPadding", "HmacSHA256");

        // operator_session_key_permissions=allow_encrypt | allow_decrypt
        byte[] aes_key_id = hex2ba("3be2b25db355fc64a0e69a50f4dbb298");
        byte[] aes_key = hex2ba("5762d22a5e17d5402dc310a7c33ce539");

        byte[] clr_data = hex2ba("4c02bcc3943aa828ecf7bbb16420572d00cabb21c3084c422217fee7fadd766d" +
                                 "4bf726a232d029a81830e40e1e12ba34ba005ca6ce8033a0e3602a52b9b8d3d4" +
                                 "b15dc458730f8affebbf35b1536c1a5d42370cf93c5b4094c0920bb1b2333f6a" +
                                 "1897c5dd62eadfc1060786b0f69f228d5d7241cc644b85c35b9a7f4b893b5b85");
        byte[] enc_data = hex2ba("ee92d402f55f1d7eef4844803d9d43a603a4dd13f4a2ad5ea7653adcefa74b06" +
                                 "ff459ab476a497567198c7cfa06d6fdd66b7924c2ca430baf534c5e00c800a06" +
                                 "d0c108057ceab2ea33671d83e35eaaf1f1ff0f7e1618d05810a47b12cbc0806f" +
                                 "d6ba8127a5e411f49b4e1790b1a6cb963e33d6cbc6569c44b4e1b28005fd1dde");

        byte[] iv = hex2ba("3ec0f3d3970fbd541ac4e7e1d06a6131");

        byte[] result = cs.decrypt(aes_key_id, enc_data, iv);
        if (Arrays.equals(clr_data, result)) {
            Log.d(TAG, "Multiple key decrypt test passed!");
        } else {
            Log.d(TAG, "Multiple key decrypt test failed!");
            mTestFailed = true;
        }

        result = cs.encrypt(aes_key_id, clr_data, iv);
        if (Arrays.equals(enc_data, result)) {
            Log.d(TAG, "Multiple key encrypt test passed!");
        } else {
            Log.d(TAG, "Multiple key encrypt test failed!");
            mTestFailed = true;
        }

        byte[] signing_key_id = hex2ba("2685086ee9cb5835b063ab20786ffd78");
        byte[] signing_key = hex2ba("b3dddf87d1cfc0b04c9253231ff89b9e374ef2f424edc7b7f4b2c10e39768ee8");

        byte[] signing_data = hex2ba("4c02bcc3943aa828ecf7bbb16420572d00cabb21c3084c422217fee7fadd766d" +
                                     "4bf726a232d029a81830e40e1e12ba34ba005ca6ce8033a0e3602a52b9b8d3d4" +
                                     "b15dc458730f8affebbf35b1536c1a5d42370cf93c5b4094c0920bb1b2333f6a" +
                                     "1897c5dd62eadfc1060786b0f69f228d5d7241cc644b85c35b9a7f4b893b5b85");

        byte[] hmacsha256 = hex2ba("5fc29a4c15fcf9e1e26b63b3be169d7f53e61e1564b92876f70c9ffd17697437");

        result = cs.sign(signing_key_id, signing_data);
        if (Arrays.equals(hmacsha256, result)) {
            Log.d(TAG, "Multiple key signing test passed!");
        } else {
            Log.d(TAG, "Multiple key signing test failed!");
            mTestFailed = true;
        }

        // operator_session_key_permissions=allow_signature_verify
        byte[] verify_key_id = hex2ba("97c003f73b1a53aa51ba54a6ef631ca0");
        byte[] verify_key = hex2ba("cfe2acb04ad5169153690c1932d5d2c6062a4607d274901e935d27b77ad48b2e");

        byte[] verify_data = hex2ba("4c02bcc3943aa828ecf7bbb16420572d00cabb21c3084c422217fee7fadd766d" +
                                    "4bf726a232d029a81830e40e1e12ba34ba005ca6ce8033a0e3602a52b9b8d3d4" +
                                    "b15dc458730f8affebbf35b1536c1a5d42370cf93c5b4094c0920bb1b2333f6a" +
                                    "1897c5dd62eadfc1060786b0f69f228d5d7241cc644b85c35b9a7f4b893b5b85");

        hmacsha256 = hex2ba("6bd61722e5cc3e698d536317309940328ab973be3a3b5705650aa09a48ebbf61");

        if (cs.verify(verify_key_id, verify_data, hmacsha256)) {
            Log.d(TAG, "Multiple key verify test passed!");
        } else {
            Log.d(TAG, "Multiple key verify test failed!");
            mTestFailed = true;
        }

        drm.closeSession(sessionId);
        stopDrm(drm);
    }

    private void testClearContentNoKeys() {
        MediaDrm drm = startDrm();
        byte[] sessionId = openSession(drm);
        testClear(sessionId);
        drm.closeSession(sessionId);
        stopDrm(drm);
    }

    private byte[] getTestModeSessionId(byte[] sessionId) {
        String testMode = new String("test_mode");
        byte[] testModeSessionId = new byte[sessionId.length + testMode.length()];
        for (int i = 0; i < sessionId.length; i++) {
            testModeSessionId[i] = sessionId[i];
        }
        for (int i = 0; i < testMode.length(); i++) {
            testModeSessionId[sessionId.length + i] = (byte)testMode.charAt(i);
        }
        return testModeSessionId;
    }

    private void sleep(int msec) {
        try {
            Thread.sleep(msec);
        } catch (InterruptedException e) {
        }
    }

    // do minimal codec setup to pass an encrypted buffer down the stack to see if it gets
    // decrypted correctly.
    public void testDecrypt(byte[] sessionId) {
        Log.i(TAG, "testDecrypt");

        MediaCrypto crypto = null;
        try {
            crypto = new MediaCrypto(kWidevineScheme, getTestModeSessionId(sessionId));
        } catch (MediaCryptoException e) {
            Log.e(TAG, "test failed due to exception: " + e.getMessage());
            e.printStackTrace();
            mTestFailed = true;
            finish();
        }

        String mime = "video/avc";
        MediaCodec codec;
        if (crypto.requiresSecureDecoderComponent(mime)) {
            codec = MediaCodec.createByCodecName(getSecureDecoderNameForMime(mime));
        } else {
            codec = MediaCodec.createDecoderByType(mime);
        }

        MediaFormat format = MediaFormat.createVideoFormat(mime, 1280, 720);
        SurfaceView sv = (SurfaceView)findViewById(R.id.surface_view);
        codec.configure(format, sv.getHolder().getSurface(), crypto, 0);
        codec.start();

        ByteBuffer[] inputBuffers = codec.getInputBuffers();
        ByteBuffer[] outputBuffers = codec.getOutputBuffers();


        int index;
        Log.i(TAG, "waiting for buffer...");
        while ((index = codec.dequeueInputBuffer(0 /* timeoutUs */)) < 0) {
            sleep(10);
        }
        Log.i(TAG, "Got index " + index);

        final int kMaxSubsamplesPerSample = 10;
        final int kMaxSampleSize = 128 * 1024;

        int clearSizes[] = new int[kMaxSubsamplesPerSample];
        int encryptedSizes[] = new int[kMaxSubsamplesPerSample];

        LinkedList<TestVector> vectors = TestVectors.GetTestVectors();
        ListIterator<TestVector> iter = vectors.listIterator(0);

        ByteBuffer refBuffer = ByteBuffer.allocate(kMaxSampleSize);

        Random rand = new Random();

        byte iv[] = null;
        byte keyID[] = null;

        int numSubSamples = 0;
        int sampleSize = 0;

        while (iter.hasNext()) {
            TestVector tv = iter.next();
            if (tv.mByteOffset == 0) {
                // start of a new sample

                if (numSubSamples > 0) {
                    // send the sample we have
                    CryptoInfo info = new CryptoInfo();
                    info.set(numSubSamples, clearSizes, encryptedSizes, keyID, iv,
                             MediaCodec.CRYPTO_MODE_AES_CTR);

                    try {
                        // Log.i(TAG,"Sending " + sampleSize + " bytes, numSubSamples=" + numSubSamples);
                        codec.queueSecureInputBuffer(index, 0 /* offset */, info,
                                                     0 /* sampleTime */, 0 /* flags */);
                    } catch (CryptoException e) {
                        // Log.i(TAG,"Checking " + sampleSize + " bytes");

                        // in test mode, the WV CryptoPlugin throws a CryptoException where the
                        // message string contains a SHA256 hash of the decrypted data, for verification
                        // purposes.
                        if (!e.getMessage().equals("secure")) {
                            Log.i(TAG, "e.getMessage()='" + e.getMessage() + "'");
                            MessageDigest digest = null;
                            try {
                                digest = MessageDigest.getInstance("SHA-256");
                            } catch (NoSuchAlgorithmException ex) {
                                ex.printStackTrace();
                                finish();
                            }
                            byte buf[] = Arrays.copyOf(refBuffer.array(), sampleSize);
                            byte[] sha256 = digest.digest(buf);
                            if (Arrays.equals(sha256, hex2ba(e.getMessage()))) {
                                Log.i(TAG, "sha256: " + e.getMessage() + " matches OK");
                            } else {
                                Log.i(TAG, "MediaCrypto sha256: " + e.getMessage() +
                                      " does not match test vector sha256: ");
                                for (int i = 0; i < sha256.length; i++) {
                                    System.out.printf("%02x", sha256[i]);
                                }
                                mTestFailed = true;
                            }
                        }
                    }

                    // clear buffers for next sample
                    numSubSamples = 0;
                    sampleSize = 0;
                    inputBuffers[index].clear();
                    refBuffer.clear();
                }
                keyID = tv.mKeyID;
                iv = tv.mIV;
            }

            // add this subsample vector to the list
            int clearSize = rand.nextInt(100);
            byte clearBuf[] = new byte[clearSize];
            for (int i = 0; i < clearBuf.length; i++) {
                clearBuf[i] = (byte)i;
            }

            clearSizes[numSubSamples] = clearSize;
            encryptedSizes[numSubSamples] = tv.mEncryptedBuf.length;
            numSubSamples++;

            inputBuffers[index].put(clearBuf, 0, clearBuf.length);
            inputBuffers[index].put(tv.mEncryptedBuf, 0, tv.mEncryptedBuf.length);

            refBuffer.put(clearBuf, 0, clearBuf.length);
            refBuffer.put(tv.mClearBuf, 0, tv.mClearBuf.length);
            sampleSize += clearSize + tv.mEncryptedBuf.length;
        }

        codec.stop();
        codec.release();
        Log.i(TAG, "testDecrypt: all done!");
    }

    // do minimal codec setup to pass a clear buffer down the stack to see if it gets
    // passed through correctly.
    public void testClear(byte[] sessionId) {
        Log.i(TAG, "testClear");

        MediaCrypto crypto = null;
        try {
            crypto = new MediaCrypto(kWidevineScheme, getTestModeSessionId(sessionId));
        } catch (MediaCryptoException e) {
            Log.e(TAG, "test failed due to exception: " + e.getMessage());
            e.printStackTrace();
            mTestFailed = true;
            finish();
        }

        String mime = "video/avc";
        MediaCodec codec;
        boolean secure = false;
        if (crypto.requiresSecureDecoderComponent(mime)) {
            codec = MediaCodec.createByCodecName(getSecureDecoderNameForMime(mime));
            secure = true;
        } else {
            codec = MediaCodec.createDecoderByType(mime);
        }

        MediaFormat format = MediaFormat.createVideoFormat(mime, 1280, 720);
        SurfaceView sv = (SurfaceView)findViewById(R.id.surface_view);
        codec.configure(format, sv.getHolder().getSurface(), crypto, 0);
        codec.start();

        ByteBuffer[] inputBuffers = codec.getInputBuffers();
        ByteBuffer[] outputBuffers = codec.getOutputBuffers();


        int index;
        Log.i(TAG, "waiting for buffer...");
        while ((index = codec.dequeueInputBuffer(0 /* timeoutUs */)) < 0) {
            sleep(10);
        }
        Log.i(TAG, "Got index " + index);

        LinkedList<TestVector> vectors = TestVectors.GetTestVectors();
        ListIterator<TestVector> iter = vectors.listIterator(0);
        while (iter.hasNext()) {
            TestVector tv = iter.next();

            inputBuffers[index].clear();
            inputBuffers[index].put(tv.mClearBuf, 0, tv.mClearBuf.length);

            try {
                if (secure) {
                    int clearSizes[] = new int[1];
                    clearSizes[0] = tv.mClearBuf.length;
                    int encryptedSizes[] = new int[1];
                    encryptedSizes[0] = 0;

                    CryptoInfo info = new CryptoInfo();
                    info.set(1, clearSizes, encryptedSizes, null, null, MediaCodec.CRYPTO_MODE_UNENCRYPTED);
                    codec.queueSecureInputBuffer(index, 0 /* offset */, info,
                                                 0 /* sampleTime */, 0 /* flags */);
                } else {
                    codec.queueInputBuffer(index, 0 /* offset */, tv.mClearBuf.length,
                                           0 /* sampleTime */, 0 /* flags */);
                }
            } catch (CryptoException e) {
                ByteBuffer refBuffer = ByteBuffer.allocate(tv.mClearBuf.length);
                refBuffer.put(tv.mClearBuf, 0, tv.mClearBuf.length);

                // in test mode, the WV CryptoPlugin throws a CryptoException where the
                // message string contains a SHA256 hash of the decrypted data, for verification
                // purposes.
                if (!e.getMessage().equals("secure")) {
                    MessageDigest digest = null;
                    try {
                        digest = MessageDigest.getInstance("SHA-256");
                    } catch (NoSuchAlgorithmException ex) {
                        ex.printStackTrace();
                        finish();
                    }
                    byte[] sha256 = digest.digest(refBuffer.array());
                    if (Arrays.equals(sha256, hex2ba(e.getMessage()))) {
                        Log.i(TAG, "sha256: " + e.getMessage() + " matches OK");
                    } else {
                        Log.i(TAG, "MediaCrypto sha256: " + e.getMessage() +
                              " does not match test vector sha256: ");
                        for (int i = 0; i < sha256.length; i++) {
                            System.out.printf("%02x", sha256[i]);
                        }
                        mTestFailed = true;
                    }
                }
            }
        }

        codec.stop();
        codec.release();
        Log.i(TAG, "testClear: all done!");
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

    private static byte[] hex2ba(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                  + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

}
