package com.famgy.fileencrypt.hook.xhook;

/**
 * Created by famgy on 18/01/2019.
 */

public class NativeHandler {
    private static final NativeHandler ourInstance = new NativeHandler();

    public static NativeHandler getInstance() {
        return ourInstance;
    }

    private NativeHandler() {
    }

    public native int refresh(boolean async);

    public native void clear();

    public native void enableDebug(boolean flag);

    public native void enableSigSegvProtection(boolean flag);

}
