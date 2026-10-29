package com.pwdkey.app;

import android.app.Activity;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.provider.OpenableColumns;

import androidx.activity.result.ActivityResult;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.ActivityCallback;
import com.getcapacitor.annotation.CapacitorPlugin;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;

/**
 * 文件选择插件。
 *
 * 为什么需要它：Capacitor 的 WebView 默认没有实现 onShowFileChooser，
 * H5 的 <input type="file"> 点了没反应。
 *
 * 必须用 Capacitor 的 startActivityForResult(call, intent, callbackName)：
 * 直接调 Activity.startActivityForResult + 覆写 handleOnActivityResult 是**不行**的，
 * Bridge 不会把结果转发给插件，导致请求永远悬挂、下次调用报 BUSY。
 *
 * 只读、只选一个文件，走 SAF，不申请存储权限。
 */
@CapacitorPlugin(name = "VaultFile")
public class VaultFilePlugin extends Plugin {

    @PluginMethod
    public void pickAndRead(PluginCall call) {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("*/*");
        try {
            startActivityForResult(call, i, "pickResult");
        } catch (Exception e) {
            call.reject("NO_PICKER", String.valueOf(e.getMessage()));
        }
    }

    @ActivityCallback
    private void pickResult(PluginCall call, ActivityResult result) {
        if (call == null) {
            return;
        }
        if (result == null
                || result.getResultCode() != Activity.RESULT_OK
                || result.getData() == null
                || result.getData().getData() == null) {
            call.reject("CANCELLED", "已取消");
            return;
        }

        Uri uri = result.getData().getData();
        try (InputStream in = getContext().getContentResolver().openInputStream(uri)) {
            if (in == null) {
                call.reject("READ_FAIL", "无法打开文件");
                return;
            }
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) {
                bos.write(buf, 0, n);
            }
            JSObject ret = new JSObject();
            ret.put("name", queryName(uri));
            ret.put("content", bos.toString("UTF-8"));
            call.resolve(ret);
        } catch (Exception e) {
            call.reject("READ_FAIL", String.valueOf(e.getMessage()));
        }
    }

    private String queryName(Uri uri) {
        try (Cursor c = getContext().getContentResolver()
                .query(uri, new String[]{OpenableColumns.DISPLAY_NAME}, null, null, null)) {
            if (c != null && c.moveToFirst()) {
                int idx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                if (idx >= 0) {
                    String s = c.getString(idx);
                    if (s != null && !s.isEmpty()) {
                        return s;
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return "backup.amfnl";
    }
}
