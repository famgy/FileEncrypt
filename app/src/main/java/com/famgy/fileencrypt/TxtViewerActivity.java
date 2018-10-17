package com.famgy.fileencrypt;

import android.os.Bundle;
import android.os.Environment;
import android.support.v7.app.ActionBar;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.MenuItem;
import android.widget.EditText;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

public class TxtViewerActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_txt_viewer);

        ActionBar actionBar = getSupportActionBar();
        if(actionBar != null){
            actionBar.setHomeButtonEnabled(true);
            actionBar.setDisplayHomeAsUpEnabled(true);
        }

        String resourcePath = Environment.getExternalStorageDirectory() + "/Download";
        File file = new File(resourcePath, "txt_test.txt");

        StringBuffer stringBuffer = new StringBuffer();
        String line = "";
//        int count = 0;
        try {
            BufferedReader bufferedReader = new BufferedReader(new FileReader(file));
            while ((line = bufferedReader.readLine()) != null) {
                stringBuffer.append(line);
                stringBuffer.append("\n");
//                count ++;
//                Log.e("TEST", "count = " + count);
            }
            bufferedReader.close();

            ((EditText)findViewById(R.id.txt_view)).setText(stringBuffer);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
            case android.R.id.home:
                try {
                    String resourcePath = Environment.getExternalStorageDirectory() + "/Download";
                    File file = new File(resourcePath, "txt_test.txt");

                    BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(file));
                    String content = ((EditText)findViewById(R.id.txt_view)).getText().toString();
                    bufferedWriter.write(content);

                    bufferedWriter.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }

                this.finish(); // back button
                return true;
        }
        return super.onOptionsItemSelected(item);
    }
}
