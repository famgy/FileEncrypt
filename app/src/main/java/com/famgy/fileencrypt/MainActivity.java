package com.famgy.fileencrypt;

import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import com.famgy.fileencrypt.filesecurity.FileSecurity;

public class MainActivity extends AppCompatActivity {

    // Used to load the 'native-lib' library on application startup.
    static {
        System.loadLibrary("native-lib");
        System.loadLibrary("inlinehook");
    }

    private Button bt_start_hook;
    private Button bt_stop_hook;
    private Button bt_encript;
    private Button bt_decrypt;
    private Boolean bHasHooked = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Example of a call to a native method
//        TextView tv = (TextView) findViewById(R.id.sample_text);
//        tv.setText(stringFromJNI());

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            if(checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED){
                AskPermission.get_permission(MainActivity.this, Manifest.permission.WRITE_EXTERNAL_STORAGE);
            }
        }

        bt_start_hook = findViewById(R.id.bt_start_hook);
        bt_start_hook.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                bHasHooked = true;
                bt_start_hook.setBackgroundColor(Color.DKGRAY);

                //ElfHookMain.startHook(getApplicationContext());
//                startInlineHook();

                //load and run the target lib
                FileSecurity.getInstance().init(getApplicationContext());
                FileSecurity.getInstance().start();
            }
        });

        bt_stop_hook = findViewById(R.id.bt_stop_hook);
        bt_stop_hook.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                bHasHooked = false;
                Drawable background = bt_stop_hook.getBackground();
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
                    bt_start_hook.setBackground(background);
                }

                Drawable backgroundClear = bt_decrypt.getBackground();
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
                    bt_encript.setBackground(backgroundClear);
                }
            }
        });


        bt_encript = findViewById(R.id.bt_encript);
        bt_encript.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (bHasHooked == true) {
                    bt_encript.setBackgroundColor(Color.RED);
                } else {
                    Toast.makeText(MainActivity.this, "Please start hook first", Toast.LENGTH_SHORT).show();
                }
            }
        });

        bt_decrypt = findViewById(R.id.bt_decrypt);
        bt_decrypt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Drawable background = bt_decrypt.getBackground();
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
                    bt_encript.setBackground(background);
                }
            }
        });

        findViewById(R.id.bt_read_pdf).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Intent intent = new Intent(MainActivity.this, PdfViewerActivity.class);
                startActivity(intent);
            }
        });

        findViewById(R.id.bt_read_txt).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Intent intent = new Intent(MainActivity.this, TxtViewerActivity.class);
                startActivity(intent);
            }
        });

        findViewById(R.id.bt_lseek).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startInlineLseek();
            }
        });
    }

    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */
    public native String stringFromJNI();
    public native void startInlineHook();
    public native void startInlineLseek();
}
