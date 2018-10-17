package com.famgy.fileencrypt;


import android.Manifest;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.support.v7.app.AppCompatActivity;
import android.widget.Toast;

import com.github.barteksc.pdfviewer.PDFView;

import java.io.File;

public class PdfViewerActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_pdf_viewer);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            if(checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED){
                AskPermission.get_permission(PdfViewerActivity.this, Manifest.permission.WRITE_EXTERNAL_STORAGE);
            }
        }

        PDFView pdfView=(PDFView)findViewById(R.id.pdf_view);
        String resourcePath = Environment.getExternalStorageDirectory() + "/Download";
        File file = new File(resourcePath, "pdf_test.pdf");
        //Uri uri = Uri.fromFile(file);
        try {
            // 加载文件
//            pdfView.fromUri(uri)
//                    .defaultPage(1)
//                    .enableDoubletap(true)
//                    .enableAnnotationRendering(true)
//                    .onLoad(PdfViewerActivity.this)
//                    .enableDoubletap(true)
//                    .swipeVertical(true)
//                    .load();
            pdfView.fromFile(file)
                    // .defaultPage(1)  //显示页数
                    .swipeHorizontal(false)  //fales 上下翻页  true 左右
                    .enableAntialiasing(true)  //是否页面渲染
                    .enableSwipe(true) //
                    //.pages(1,2)   //可以过滤的页数
                    .load();
        } catch (Exception ex) {
            Toast.makeText(PdfViewerActivity.this,"文件不存在或已损坏",Toast.LENGTH_SHORT).show();
            finish();
        }
    }
}
