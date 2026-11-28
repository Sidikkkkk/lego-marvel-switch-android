package org.sidikkkkk.switchport;

import android.app.Activity;
import android.content.Intent;
import android.content.res.AssetFileDescriptor;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.DocumentsContract;
import android.provider.DocumentsContract.Document;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class MainActivity extends Activity {
    private static final int OPEN_MAIN = 1;
    private static final int OPEN_EXEFS = 2;
    private final ExecutorService inspector = Executors.newSingleThreadExecutor();
    private TextView status;

    private record ModuleFile(String name, Uri uri) {}

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

        Button chooseFolder = new Button(this);
        chooseFolder.setText("Pilih folder ExeFS");
        chooseFolder.setOnClickListener(view -> {
            Intent picker = new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE);
            picker.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            startActivityForResult(picker, OPEN_EXEFS);
        });
        content.addView(chooseFolder);

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
        if ((requestCode != OPEN_MAIN && requestCode != OPEN_EXEFS) || resultCode != RESULT_OK || result == null
                || result.getData() == null) {
            return;
        }
        Uri uri = result.getData();
        boolean folder = requestCode == OPEN_EXEFS;
        status.setText(folder ? "Sedang memeriksa modul ExeFS…" : "Sedang memeriksa segmen NSO0…");
        inspector.execute(() -> {
            String report;
            try {
                report = folder ? inspectFolder(uri) : inspectFile(uri, null, null);
            } catch (IOException | SecurityException | IllegalArgumentException error) {
                report = errorMessage(error);
            }
            String completedReport = report;
            runOnUiThread(() -> {
                if (!isDestroyed()) {
                    status.setText(completedReport);
                }
            });
        });
    }

    @Override
    protected void onDestroy() {
        inspector.shutdownNow();
        super.onDestroy();
    }

    private String inspectFolder(Uri tree) throws IOException {
        List<ModuleFile> modules = listRegularFiles(tree);
        ModuleFile main = null;
        for (ModuleFile module : modules) {
            if (module.name().equals("main")) {
                if (main != null) {
                    throw new IOException("Ada beberapa file bernama main di folder ini.");
                }
                main = module;
            }
        }
        if (main == null) {
            throw new IOException("File main tidak ditemukan. Pilih folder exefs yang langsung berisi main.");
        }

        NsoImportAudit audit = new NsoImportAudit();
        String mainReport = inspectFile(main.uri(), audit, null);
        StringBuilder moduleReport = new StringBuilder();
        if (audit.hasImports()) {
            modules.sort(Comparator.comparing(ModuleFile::name));
            for (ModuleFile module : modules) {
                if (Thread.currentThread().isInterrupted()) {
                    throw new InterruptedIOException("Pemeriksaan folder dibatalkan.");
                }
                if (module == main) {
                    continue;
                }
                try {
                    String matches = inspectFile(module.uri(), audit, module.name());
                    if (matches != null) {
                        moduleReport.append(module.name()).append("  ").append(matches).append('\n');
                    }
                } catch (InterruptedIOException error) {
                    throw error;
                } catch (IOException | SecurityException | IllegalArgumentException error) {
                    moduleReport.append(module.name()).append("  Gagal diperiksa. ")
                            .append(errorMessage(error)).append('\n');
                }
            }
            if (moduleReport.length() == 0) {
                moduleReport.append("Tidak ada modul NSO0 lain di folder ini.\n");
            }
        }
        return audit.report() + '\n' + moduleReport + '\n' + mainReport;
    }

    private List<ModuleFile> listRegularFiles(Uri tree) throws IOException {
        Uri children = DocumentsContract.buildChildDocumentsUriUsingTree(tree, DocumentsContract.getTreeDocumentId(tree));
        String[] columns = {Document.COLUMN_DOCUMENT_ID, Document.COLUMN_DISPLAY_NAME, Document.COLUMN_MIME_TYPE};
        List<ModuleFile> files = new ArrayList<>();
        try (Cursor rows = getContentResolver().query(children, columns, null, null, null)) {
            if (rows == null) {
                throw new IOException("Folder ExeFS gagal dibaca.");
            }
            int idColumn = rows.getColumnIndexOrThrow(Document.COLUMN_DOCUMENT_ID);
            int nameColumn = rows.getColumnIndexOrThrow(Document.COLUMN_DISPLAY_NAME);
            int mimeColumn = rows.getColumnIndexOrThrow(Document.COLUMN_MIME_TYPE);
            while (rows.moveToNext()) {
                String id = rows.getString(idColumn);
                String name = rows.getString(nameColumn);
                if (id != null && name != null && !Document.MIME_TYPE_DIR.equals(rows.getString(mimeColumn))) {
                    files.add(new ModuleFile(name, DocumentsContract.buildDocumentUriUsingTree(tree, id)));
                }
            }
        }
        return files;
    }

    private String inspectFile(Uri uri, NsoImportAudit audit, String exportModule) throws IOException {
        try (AssetFileDescriptor file = getContentResolver().openAssetFileDescriptor(uri, "r")) {
            if (file == null) {
                throw new IOException("File tidak bisa dibuka.");
            }
            try (InputStream input = file.createInputStream()) {
                Runtime runtime = Runtime.getRuntime();
                long usedHeap = runtime.totalMemory() - runtime.freeMemory();
                long memoryBudget = Math.max(0L, runtime.maxMemory() - usedHeap) / 2;
                if (exportModule != null) {
                    return NsoHeader.inspectExportModule(new BufferedInputStream(input), file.getLength(),
                            memoryBudget, audit, exportModule);
                }
                if (audit != null) {
                    return NsoHeader.inspectFolderMain(input, file.getLength(), memoryBudget, audit);
                }
                return NsoHeader.inspectWithRelativeTest(input, file.getLength(), memoryBudget).report();
            }
        }
    }

    private static String errorMessage(Exception error) {
        String message = error.getMessage();
        return message == null ? "File gagal dibaca." : message;
    }
}
