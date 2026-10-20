package com.pwdkey.app;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.FragmentActivity;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * BiometricWrapPlugin - 生物认证包裹层（PwdKey App v1.1）
 *
 * 设计要点（与固件零耦合，全部在手机侧）：
 *
 *   1) 外层：Android Keystore 里的 AES-256-GCM 密钥 K_bio
 *      - setUserAuthenticationRequired(true) + setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)
 *        => 每次使用都必须现场通过一次强生物认证（指纹 / 3D 面容），密钥本身不可导出。
 *      - setIsStrongBoxBacked(true) 优先，机型不支持时自动回落 TEE。
 *      - setInvalidatedByBiometricEnrollment(true)：新增/删除指纹后密钥永久失效，
 *        旧信封解不开 —— 强制用户回落到主密码重新开启，这是有意的安全行为。
 *
 *   2) 内层：6 位 PIN
 *      envelope（100 字节）=
 *        magic(2) | ver(1) | rsv(1) | pinIter(4,LE) | deviceSalt(16) | pinSalt(16)   <- 40 字节头部，作 AAD
 *        | iv(12) | ct(32) | tag(16)                                                 <- AES-GCM(K_pin, KEK)
 *      K_pin = PBKDF2-HMAC-SHA256(PIN, pinSalt, pinIter)
 *
 *   3) 信封再整体用 K_bio 包裹后存 SharedPreferences。
 *      => 没有通过生物认证，连"可以拿来爆破 PIN 的那段密文"都拿不到。
 *
 *   4) 防"改密码后解出失效 KEK"：信封头部里带 deviceSalt + pinIter，JS 侧会先与
 *      DEVICE_INFO 回报的 salt 比对；不一致则不发起 AUTH_VERIFY（避免消耗设备的
 *      失败计数、把设备打进永久锁定），直接要求用主密码解锁。
 *
 * 安全边界（务必如实告知用户）：
 *   - 本层挡的是"拿到手机的人"。手机被 root / 内存被 hook 时，KEK 在解封瞬间
 *     就是明文，任何手机端方案都挡不住。
 *   - PIN 只有 20 bit 熵。它之所以还能用，是因为外层 TEE 生物认证是一道硬门；
 *     PIN 只是过了这道门之后的减速带，不构成独立的抗爆破能力。
 */
@CapacitorPlugin(name = "BiometricWrap")
public class BiometricWrapPlugin extends Plugin {

    /* ---------------- 常量 ---------------- */

    private static final String KEY_ALIAS = "pwdkey_bio_wrap_v1";
    private static final String PREFS = "pwdkey_bio";
    private static final String P_IV = "wrap_iv";
    private static final String P_CT = "wrap_ct";

    private static final int ENVELOPE_LEN = 100;
    private static final int HEADER_LEN = 40;
    private static final byte MAGIC0 = 0x50;   // 'P'
    private static final byte MAGIC1 = 0x57;   // 'W'
    private static final byte ENV_VER = 1;

    private static final int MIN_PIN_ITER = 100_000;
    private static final int MAX_PIN_ITER = 4_000_000;

    /* 同一时刻只允许一个系统生物弹窗 */
    private boolean prompting = false;

    /* ---------------- 工具 ---------------- */

    private SharedPreferences prefs() {
        return getContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    private static String b64(byte[] b) {
        return Base64.encodeToString(b, Base64.NO_WRAP);
    }

    private static byte[] unb64(String s) {
        return Base64.decode(s, Base64.NO_WRAP);
    }

    private static void wipe(byte[] b) {
        if (b != null) {
            Arrays.fill(b, (byte) 0);
        }
    }

    private static String reasonText(int reason) {
        switch (reason) {
            case BiometricManager.BIOMETRIC_SUCCESS:
                return "设备支持强生物认证";
            case BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE:
                return "设备没有生物识别硬件";
            case BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE:
                return "生物识别硬件当前不可用";
            case BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED:
                return "系统里还没有录入指纹或面容";
            case BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED:
                return "系统安全更新缺失，暂不可用";
            case BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED:
                return "当前系统版本不支持该认证方式";
            case BiometricManager.BIOMETRIC_STATUS_UNKNOWN:
                return "无法确定生物识别状态";
            default:
                return "生物识别不可用（" + reason + "）";
        }
    }

    /** 生物认证错误码 -> 机器可读字符串 */
    private static String mapAuthError(int code) {
        switch (code) {
            case BiometricPrompt.ERROR_NEGATIVE_BUTTON:
            case BiometricPrompt.ERROR_USER_CANCELED:
            case BiometricPrompt.ERROR_CANCELED:
                return "USER_CANCELED";
            case BiometricPrompt.ERROR_LOCKOUT:
                return "LOCKOUT";
            case BiometricPrompt.ERROR_LOCKOUT_PERMANENT:
                return "LOCKOUT_PERMANENT";
            case BiometricPrompt.ERROR_NO_BIOMETRICS:
                return "NO_BIOMETRICS";
            case BiometricPrompt.ERROR_HW_NOT_PRESENT:
            case BiometricPrompt.ERROR_HW_UNAVAILABLE:
                return "NO_HARDWARE";
            case BiometricPrompt.ERROR_SECURITY_UPDATE_REQUIRED:
                return "SECURITY_UPDATE_REQUIRED";
            default:
                return "BIO_ERROR_" + code;
        }
    }

    /* ---------------- Keystore ---------------- */

    private KeyGenParameterSpec buildSpec(boolean strongBox) {
        KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(true)
                .setRandomizedEncryptionRequired(true)
                /* 新增/删除指纹 => 密钥永久失效（只对免密-凭证的密钥生效，正是本场景） */
                .setInvalidatedByBiometricEnrollment(true);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            /* timeout=0 表示"每次使用都要认证"，且只允许强生物（Class 3） */
            b.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG);
        } else {
            /* API 26-29：-1 即"每次使用都要认证" */
            b.setUserAuthenticationValidityDurationSeconds(-1);
        }

        if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            b.setIsStrongBoxBacked(true);
        }
        return b.build();
    }

    /** 取已有密钥；不存在则新建（StrongBox 优先，不可用则回落 TEE） */
    private SecretKey getOrCreateKey() throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        if (ks.containsAlias(KEY_ALIAS)) {
            return (SecretKey) ks.getKey(KEY_ALIAS, null);
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                return generateKey(true);
            } catch (Exception e) {
                /* 没有 StrongBox，或该 ROM 不接受这个参数组合 —— 清掉半成品后回落。
                   这里刻意不 catch StrongBoxUnavailableException 这个具体类型：
                   它在 API 28 才存在，直接引用会在 API 26/27 上引发类解析问题。 */
                deleteKey();
            }
        }
        return generateKey(false);
    }

    private SecretKey generateKey(boolean strongBox) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        kg.init(buildSpec(strongBox));
        return kg.generateKey();
    }

    private boolean hasKey() {
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            return ks.containsAlias(KEY_ALIAS);
        } catch (Exception e) {
            return false;
        }
    }

    private void deleteKey() {
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            if (ks.containsAlias(KEY_ALIAS)) {
                ks.deleteEntry(KEY_ALIAS);
            }
        } catch (Exception ignored) {
        }
    }

    /* ---------------- PIN 层（纯计算，不做认证） ---------------- */

    private static byte[] pbkdf2(String pin, byte[] salt, int iter) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(pin.toCharArray(), salt, iter, 256);
        try {
            SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return f.generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }

    private static byte[] buildEnvelope(String pin, byte[] kek, byte[] deviceSalt,
                                        int pinIter) throws Exception {
        byte[] pinSalt = new byte[16];
        new SecureRandom().nextBytes(pinSalt);

        ByteBuffer head = ByteBuffer.allocate(HEADER_LEN).order(ByteOrder.LITTLE_ENDIAN);
        head.put(MAGIC0).put(MAGIC1).put(ENV_VER).put((byte) 0);
        head.putInt(pinIter);
        head.put(deviceSalt);
        head.put(pinSalt);
        byte[] aad = head.array();

        byte[] kPin = pbkdf2(pin, pinSalt, pinIter);
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(kPin, "AES"));
            c.updateAAD(aad);
            byte[] ctTag = c.doFinal(kek);
            byte[] iv = c.getIV();

            ByteBuffer out = ByteBuffer.allocate(ENVELOPE_LEN);
            out.put(aad).put(iv).put(ctTag);
            return out.array();
        } finally {
            wipe(kPin);
        }
    }

    /* ---------------- 系统生物弹窗 ---------------- */

    private BiometricPrompt.PromptInfo buildPromptInfo(String title, String subtitle) {
        return new BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setSubtitle(subtitle)
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .setNegativeButtonText("取消")
                .setConfirmationRequired(false)
                .build();
    }

    private interface CipherDone {
        void onSuccess(Cipher cipher);

        void onError(String code, String message);
    }

    /**
     * 弹一次生物认证，成功后把已授权的 Cipher 交给回调。
     * @param cipher 已 init、且绑定 CryptoObject 的 Cipher（加密或解密）
     */
    private void authenticate(final PluginCall call, final Cipher cipher,
                              final String title, final String subtitle,
                              final CipherDone done) {
        if (prompting) {
            call.reject("上一次认证还没结束", "BUSY");
            return;
        }
        final FragmentActivity act = (FragmentActivity) getActivity();
        if (act == null) {
            call.reject("界面已销毁", "ACTIVITY_NULL");
            return;
        }
        prompting = true;

        act.runOnUiThread(() -> {
            try {
                BiometricPrompt prompt = new BiometricPrompt(
                        act,
                        ContextCompat.getMainExecutor(getContext()),
                        new BiometricPrompt.AuthenticationCallback() {
                            @Override
                            public void onAuthenticationSucceeded(
                                    BiometricPrompt.AuthenticationResult result) {
                                prompting = false;
                                BiometricPrompt.CryptoObject co = result.getCryptoObject();
                                if (co == null || co.getCipher() == null) {
                                    done.onError("INTERNAL", "认证结果缺少 Cipher");
                                    return;
                                }
                                done.onSuccess(co.getCipher());
                            }

                            @Override
                            public void onAuthenticationError(int code, CharSequence msg) {
                                prompting = false;
                                done.onError(mapAuthError(code), msg == null ? "" : msg.toString());
                            }

                            @Override
                            public void onAuthenticationFailed() {
                                /* 单次指纹不匹配：系统会自己提示重试，这里不结束调用 */
                            }
                        });

                prompt.authenticate(buildPromptInfo(title, subtitle),
                        new BiometricPrompt.CryptoObject(cipher));
            } catch (Exception e) {
                prompting = false;
                done.onError("INTERNAL", String.valueOf(e.getMessage()));
            }
        });
    }

    /* ---------------- 对外方法 ---------------- */

    @PluginMethod
    public void status(PluginCall call) {
        BiometricManager bm = BiometricManager.from(getContext());
        int can = bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG);

        JSObject ret = new JSObject();
        ret.put("available", can == BiometricManager.BIOMETRIC_SUCCESS);
        ret.put("reason", can);
        ret.put("reasonText", reasonText(can));
        ret.put("hasEnroll", prefs().contains(P_CT) && prefs().contains(P_IV) && hasKey());
        call.resolve(ret);
    }

    /**
     * 开启生物解锁：把 JS 侧生成的 FK 信封用 K_bio 加密后落盘。
     * 入参 { kekB64, pin, pinIter, deviceSaltB64 }
     */
    @PluginMethod
    public void enroll(final PluginCall call) {
        final String kekB64 = call.getString("kekB64");
        final String pin = call.getString("pin");
        final String saltB64 = call.getString("deviceSaltB64");
        final Integer pinIter = call.getInt("pinIter");

        if (kekB64 == null || pin == null || saltB64 == null || pinIter == null) {
            call.reject("缺少参数", "BAD_ARGS");
            return;
        }
        if (pinIter < MIN_PIN_ITER || pinIter > MAX_PIN_ITER) {
            call.reject("PIN 迭代次数越界", "BAD_ARGS");
            return;
        }

        byte[] kekTmp = null;
        byte[] envelopeTmp = null;
        try {
            kekTmp = unb64(kekB64);
            byte[] deviceSalt = unb64(saltB64);
            if (kekTmp.length != 32 || deviceSalt.length != 16) {
                call.reject("KEK 或 salt 长度不对", "BAD_ARGS");
                return;
            }
            envelopeTmp = buildEnvelope(pin, kekTmp, deviceSalt, pinIter);
        } catch (Exception e) {
            wipe(kekTmp);
            call.reject("信封构造失败：" + e.getMessage(), "INTERNAL");
            return;
        }
        final byte[] kek = kekTmp;
        final byte[] envelope = envelopeTmp;

        try {
            SecretKey key = getOrCreateKey();
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key);

            authenticate(call, cipher, "开启生物解锁", "验证指纹或面容以保存密钥", new CipherDone() {
                @Override
                public void onSuccess(Cipher c) {
                    try {
                        byte[] ct = c.doFinal(envelope);
                        byte[] iv = c.getIV();
                        prefs().edit()
                                .putString(P_IV, b64(iv))
                                .putString(P_CT, b64(ct))
                                .apply();
                        wipe(envelope);
                        wipe(kek);
                        JSObject r = new JSObject();
                        r.put("ok", true);
                        call.resolve(r);
                    } catch (Exception e) {
                        call.reject("保存失败：" + e.getMessage(), "INTERNAL");
                    }
                }

                @Override
                public void onError(String code, String message) {
                    call.reject(message == null || message.isEmpty() ? code : message, code);
                }
            });
        } catch (KeyPermanentlyInvalidatedException e) {
            clearAll();
            call.reject("生物信息已变更，密钥失效", "KEY_INVALIDATED");
        } catch (Exception e) {
            call.reject("Keystore 初始化失败：" + e.getMessage(), "INTERNAL");
        }
    }

    /**
     * 解封外层：只做生物认证，返回内层信封（还没解 PIN）。
     * 返回 { envelopeB64 }
     */
    @PluginMethod
    public void unwrap(final PluginCall call) {
        final String ivB64 = prefs().getString(P_IV, null);
        final String ctB64 = prefs().getString(P_CT, null);
        if (ivB64 == null || ctB64 == null) {
            call.reject("尚未开启生物解锁", "NO_ENROLL");
            return;
        }

        final byte[] iv = unb64(ivB64);
        final byte[] ct = unb64(ctB64);

        try {
            SecretKey key = getOrCreateKey();
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));

            authenticate(call, cipher, "解锁 PwdKey", "验证指纹或面容", new CipherDone() {
                @Override
                public void onSuccess(Cipher c) {
                    try {
                        byte[] env = c.doFinal(ct);
                        if (env.length != ENVELOPE_LEN) {
                            wipe(env);
                            call.reject("信封长度异常", "BAD_ENVELOPE");
                            return;
                        }
                        JSObject r = new JSObject();
                        r.put("envelopeB64", b64(env));
                        wipe(env);
                        call.resolve(r);
                    } catch (AEADBadTagException e) {
                        deadEnvelope(call);
                    } catch (Exception e) {
                        call.reject("解封失败：" + e.getMessage(), "INTERNAL");
                    }
                }

                @Override
                public void onError(String code, String message) {
                    call.reject(message == null || message.isEmpty() ? code : message, code);
                }
            });
        } catch (KeyPermanentlyInvalidatedException e) {
            deadEnvelope(call);
        } catch (Exception e) {
            call.reject("Keystore 初始化失败：" + e.getMessage(), "INTERNAL");
        }
    }

    /** 密钥被生物信息变更作废：清掉本地信封，让用户回到主密码 */
    private void deadEnvelope(PluginCall call) {
        clearAll();
        call.reject("生物信息已变更，请用主密码解锁后重新开启", "KEY_INVALIDATED");
    }

    /**
     * 解内层：用 6 位 PIN 解出 KEK（纯计算，不含任何认证）。
     * 入参 { envelopeB64, pin }
     * 返回 { kekB64, deviceSaltB64, pinIter }
     */
    @PluginMethod
    public void open(final PluginCall call) {
        final String envB64 = call.getString("envelopeB64");
        final String pin = call.getString("pin");
        if (envB64 == null || pin == null) {
            call.reject("缺少参数", "BAD_ARGS");
            return;
        }

        byte[] env = null;
        byte[] kPin = null;
        try {
            env = unb64(envB64);
            if (env.length != ENVELOPE_LEN || env[0] != MAGIC0 || env[1] != MAGIC1) {
                call.reject("信封格式不正确", "BAD_ENVELOPE");
                return;
            }
            if (env[2] != ENV_VER) {
                call.reject("信封版本不支持", "BAD_ENVELOPE");
                return;
            }

            ByteBuffer buf = ByteBuffer.wrap(env).order(ByteOrder.LITTLE_ENDIAN);
            int pinIter = buf.getInt(4);
            if (pinIter < MIN_PIN_ITER || pinIter > MAX_PIN_ITER) {
                call.reject("迭代次数异常", "BAD_ENVELOPE");
                return;
            }

            byte[] deviceSalt = new byte[16];
            byte[] pinSalt = new byte[16];
            buf.position(8);
            buf.get(deviceSalt);
            buf.get(pinSalt);
            byte[] iv = new byte[12];
            buf.get(iv);
            byte[] ctTag = new byte[48];   // 32 字节 KEK + 16 字节 tag
            buf.get(ctTag);

            byte[] aad = Arrays.copyOfRange(env, 0, HEADER_LEN);
            kPin = pbkdf2(pin, pinSalt, pinIter);

            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(kPin, "AES"),
                    new GCMParameterSpec(128, iv));
            c.updateAAD(aad);

            byte[] kek;
            try {
                kek = c.doFinal(ctTag);
            } catch (AEADBadTagException e) {
                call.reject("PIN 不正确", "PIN_INVALID");
                return;
            }

            JSObject r = new JSObject();
            r.put("kekB64", b64(kek));
            r.put("deviceSaltB64", b64(deviceSalt));
            r.put("pinIter", pinIter);
            wipe(kek);
            call.resolve(r);
        } catch (Exception e) {
            call.reject("解封失败：" + e.getMessage(), "INTERNAL");
        } finally {
            wipe(env);
            wipe(kPin);
        }
    }

    /** 关闭生物解锁：删除信封与 Keystore 密钥 */
    @PluginMethod
    public void clear(PluginCall call) {
        clearAll();
        JSObject r = new JSObject();
        r.put("ok", true);
        call.resolve(r);
    }

    private void clearAll() {
        prefs().edit().remove(P_IV).remove(P_CT).apply();
        deleteKey();
    }
}
