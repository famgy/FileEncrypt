package com.famgy.fileencrypt;

import android.app.Activity;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.support.v4.app.ActivityCompat;
import android.support.v4.content.ContextCompat;

/**
 * Created by uniking on 17-8-3.
 */

public class AskPermission {
    public static void ask_permission(Activity activity, Context context, String permission) {
        // 要申请的权限
//        private String[] permissions = {Manifest.permission.READ_PHONE_STATE,Manifest.permission.WRITE_EXTERNAL_STORAGE};
        String[] permissions = {permission};

        // 版本判断。当手机系统大于 23 时，才有必要去判断权限是否获取
        if (Build.VERSION.SDK_INT >= 23) {

            // 检查该权限是否已经获取
            int i = ContextCompat.checkSelfPermission(context, permission);
            // 权限是否已经 授权 GRANTED---授权  DINIED---拒绝
            if (i != PackageManager.PERMISSION_GRANTED) {
                // 如果没有授予该权限，就去提示用户请求
                ActivityCompat.requestPermissions(activity, permissions, 1);
            }

        }
    }

    public static void get_permission(Activity activity, String permission)
    {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
        {
            if (ActivityCompat.checkSelfPermission(activity, permission) != PackageManager.PERMISSION_GRANTED) {
                ask_permission(activity, activity, permission);
            }
        }
    }
}
