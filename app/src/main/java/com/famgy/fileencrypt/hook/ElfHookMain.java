package com.famgy.fileencrypt.hook;

import android.content.Context;

import com.famgy.fileencrypt.hook.xhook.XHook;
import com.famgy.fileencrypt.hook.xhookapply.XHookApply;

/**
 * Created by uniking on 17-9-25.
 */

public class ElfHookMain {
    private static boolean b_load = false;

    public static void startHook(Context context)
    {
        //load xhook
        XHook.getInstance().init(context.getApplicationContext());
        if(!XHook.getInstance().isInited()) {
            return;
        }

        //load and run your biz lib (for register hook points)
        XHookApply.getInstance().init();
        XHookApply.getInstance().start();

        //xhook do refresh
        XHook.getInstance().refresh(false);

        try {
            Thread.sleep(200);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        //xhook do refresh again
        XHook.getInstance().refresh(false);

        //xhook do refresh again for some reason,
        //maybe called after some System.loadLibrary() and System.load()
        //*
        new Thread(new Runnable() {
            @Override
            public void run() {
                while(true)
                {
                    XHook.getInstance().refresh(true);

                    try {
                        Thread.sleep(5000);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
            }
        }).start();
    }
}
