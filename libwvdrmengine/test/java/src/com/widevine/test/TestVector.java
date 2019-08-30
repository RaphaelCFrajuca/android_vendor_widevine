/*
 * (c)Copyright 2011 Widevine Technologies, Inc
 */

package com.widevine.test;

import java.util.LinkedList;
import android.util.Log;

public class TestVector {
    private final static String TAG = "CENC-TestVector";

    public TestVector(String keyID, String iv,
                      String encBuf, String clrBuf, int offset) {
        mKeyID = hex2ba(keyID);
        mIV = hex2ba(iv);
        mEncryptedBuf = hex2ba(encBuf);
        mClearBuf = hex2ba(clrBuf);
        mByteOffset = offset;
    }

    public final byte[] mKeyID;
    public final byte[] mIV;
    public final byte[] mEncryptedBuf;
    public final byte[] mClearBuf;
    public final int mByteOffset;

    private static byte[] hex2ba(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                  + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
};


