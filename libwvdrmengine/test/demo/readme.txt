ExoPlayerDemo.apk can be used to do end-to-end verification of your Modular DRM.

To install, side load ExoPlayerDemo.apk app to your device:

  adb install ExoPlayerDemo.apk

To run, launch ExoPlayer, then choose the Revenge (DASH CENC) clip, which is encrypted
   using DASH Common Encryption.  Then press "Play" to start playback.  The other clips
   in the list are clear (i.e. not encrypted).

Notes:

- The demo app shows up in the launcher as "ExoPlayer"

- The demo app contains a crude adaptive algorithm. It starts at 144p and will not switch up for 15
  seconds. This is expected (and has the benefit of more or less guaranteeing there's at least one
  switch during any playback beyond this length).

- If your device is running KLP, and the decoder claims to support adaptive, then ExoPlayer will
  do seamless resolution switching. If the decoder doesn't claim this then you'll still get the
  old nearly-seamless-switch (codec release/re-acquire) behavior.

- If your device is running KLP, the player will attempt to hook into the new
  AudioTrack.getTimestamp API to do A/V sync. It will fall back to how it used to do things if
  the API isn't available.

- The apk is still built against API level 18. The features above are accessed via reflection.

