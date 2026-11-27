package org.sidikkkkk.switchport;

import android.app.Activity;
import android.content.Intent;
import android.content.res.AssetFileDescriptor;
import android.net.Uri;
import android.os.Bundle;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class MainActivity extends Activity {
    private static final int OPEN_MAIN = 1;
    private final ExecutorService inspector = Executors.newSingleThreadExecutor();
    private TextView status;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        int padding = Math.round(20 * getResources().getDisplayMetrics().density);
        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(padding, padding, padding, padding);

        Button select = new Button(this);
        select.setText("Pilih file main dari ExeFS");
        select.setOnClickListener(view -> {
            Intent picker = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            picker.addCategory(Intent.CATEGORY_OPENABLE);
            picker.setType("*/*");
            startActivityForResult(picker, OPEN_MAIN);
        });
        content.addView(select);

        status = new TextView(this);
        status.setTextIsSelectable(true);
        status.setText("Pemeriksaan file game Switch. Eksekusi game belum tersedia.");
        content.addView(status);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(content);
        setContentView(scroll);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent result) {
        super.onActivityResult(requestCode, resultCode, result);
        if (requestCode != OPEN_MAIN || resultCode != RESULT_OK || result == null
                || result.getData() == null) {
            return;
        }
        Uri uri = result.getData();
        status.setText("Sedang memeriksa segmen NSO0…");
        inspector.execute(() -> {
            String report = inspect(uri);
            runOnUiThread(() -> {
                if (!isDestroyed()) {
                    status.setText(report);
                }
            });
        });
    }

    @Override
    protected void onDestroy() {
        inspector.shutdownNow();
        super.onDestroy();
    }

    private String inspect(Uri uri) {
        try (AssetFileDescriptor file = getContentResolver().openAssetFileDescriptor(uri, "r")) {
            if (file == null) {
                return "File tidak bisa dibuka.";
            }
            try (InputStream input = file.createInputStream()) {
                return NsoHeader.inspect(input, file.getLength());
            }
        } catch (IOException | SecurityException error) {
            String message = error.getMessage();
            return message == null ? "File gagal dibaca." : message;
        }
    }
}
