idf_component_register(
    SRCS "main.c" "kdf.c" "sec_store.c" "sec_session.c" "btn_confirm.c"
         "ble_hid_kbd.c" "ble_mgmt_svc.c" "ble_gap_mgr.c" "audit_log.c"
         "host_reg.c" "host_name_probe.c" "usb_hid_kbd.c" "shamir.c"
    INCLUDE_DIRS "."
    REQUIRES bt nvs_flash mbedtls esp_timer esp_driver_gpio esp_partition
             espressif__esp_tinyusb
)
