package com.famgy.fileencrypt.filesecurity;

import android.content.Context;
import android.util.Log;

public class FileSecurity {
    private static final FileSecurity ourInstance = new FileSecurity();
    private static boolean inited = false;

    public static FileSecurity getInstance() {
        return ourInstance;
    }

    private FileSecurity() {
    }

    /**
     * Init filesecurity.
     * @param ctx The application context.
     * @return true if successful, false otherwise.
     */
    public synchronized boolean init(Context ctx) {
        if(inited) {
            return true;
        }

        try {
            System.loadLibrary("filesecurity");
            inited = true;
        } catch (Throwable e) {
            try {
                System.load(ctx.getFilesDir().getParent() + "/lib/libfilesecurity.so");
                inited = true;
            } catch (Throwable ex) {
                ex.printStackTrace();
                Log.e("filesecurity", "load libfilesecurity.so failed");
            }
        }
        return inited;
    }

    public synchronized void start() {
        NativeHandler.getInstance().start();
    }
}
