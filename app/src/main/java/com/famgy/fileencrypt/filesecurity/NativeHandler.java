package com.famgy.fileencrypt.filesecurity;

/**
 * Created by famgy on 18/01/2019.
 */

public class NativeHandler {
    private static final NativeHandler ourInstance = new NativeHandler();
    private static boolean started = false;

    public static NativeHandler getInstance() {
        return ourInstance;
    }

    private NativeHandler() {
    }

    public void start() {
        if(started) {
            return;
        }

        startFileSecurity();
    }

    public native void startFileSecurity();

}
