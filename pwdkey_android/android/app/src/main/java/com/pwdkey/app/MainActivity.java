package com.pwdkey.app;

import android.os.Bundle;

import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        /* 自定义插件必须在 super.onCreate 之前注册 */
        registerPlugin(BiometricWrapPlugin.class);
        registerPlugin(VaultFilePlugin.class);
        super.onCreate(savedInstanceState);
    }
}
