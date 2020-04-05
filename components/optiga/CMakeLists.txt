set(COMPONENT_ADD_INCLUDEDIRS "${CMAKE_CURRENT_LIST_DIR}/optiga-trust-m/optiga/include")

set(COMPONENT_SRCS
    "${CMAKE_CURRENT_LIST_DIR}/optiga-trust-m/optiga/optiga_trust.c"
	"${CMAKE_CURRENT_LIST_DIR}/optiga-trust-m/examples/mbedtls_port/trustm_ecdh.c"
	"${CMAKE_CURRENT_LIST_DIR}/optiga-trust-m/examples/mbedtls_port/trustm_ecdsa.c"
	"${CMAKE_CURRENT_LIST_DIR}/optiga-trust-m/examples/mbedtls_port/trustm_rsa.c"
	"${CMAKE_CURRENT_LIST_DIR}/optiga-trust-m/pal/esp32_freertos/pal.c"
	"${CMAKE_CURRENT_LIST_DIR}/optiga-trust-m/pal/esp32_freertos/pal_gpio.c"
	"${CMAKE_CURRENT_LIST_DIR}/optiga-trust-m/pal/esp32_freertos/pal_i2c.c"
	"${CMAKE_CURRENT_LIST_DIR}/optiga-trust-m/pal/esp32_freertos/pal_ifx_i2c_config.c"
	"${CMAKE_CURRENT_LIST_DIR}/optiga-trust-m/pal/esp32_freertos/pal_logger.c"
	"${CMAKE_CURRENT_LIST_DIR}/optiga-trust-m/pal/esp32_freertos/pal_os_datastore.c"
	"${CMAKE_CURRENT_LIST_DIR}/optiga-trust-m/pal/esp32_freertos/pal_os_event.c"
	"${CMAKE_CURRENT_LIST_DIR}/optiga-trust-m/pal/esp32_freertos/pal_os_lock.c"
	"${CMAKE_CURRENT_LIST_DIR}/optiga-trust-m/pal/esp32_freertos/pal_os_timer.c"
	"${CMAKE_CURRENT_LIST_DIR}/optiga-trust-m/pal/pal_crypt_mbedtls.c"
	"${CMAKE_CURRENT_LIST_DIR}/optiga-trust-m/optiga/cmd/optiga_cmd.c"
	"${CMAKE_CURRENT_LIST_DIR}/optiga-trust-m/optiga/common/optiga_lib_common.c"
	"${CMAKE_CURRENT_LIST_DIR}/optiga-trust-m/optiga/common/optiga_lib_logger.c"
	"${CMAKE_CURRENT_LIST_DIR}/optiga-trust-m/optiga/comms/optiga_comms_ifx_i2c.c"
	"${CMAKE_CURRENT_LIST_DIR}/optiga-trust-m/optiga/comms/ifx_i2c/ifx_i2c.c"
	"${CMAKE_CURRENT_LIST_DIR}/optiga-trust-m/optiga/comms/ifx_i2c/ifx_i2c_config.c"
	"${CMAKE_CURRENT_LIST_DIR}/optiga-trust-m/optiga/comms/ifx_i2c/ifx_i2c_data_link_layer.c"
	"${CMAKE_CURRENT_LIST_DIR}/optiga-trust-m/optiga/comms/ifx_i2c/ifx_i2c_physical_layer.c"
	"${CMAKE_CURRENT_LIST_DIR}/optiga-trust-m/optiga/comms/ifx_i2c/ifx_i2c_presentation_layer.c"
	"${CMAKE_CURRENT_LIST_DIR}/optiga-trust-m/optiga/comms/ifx_i2c/ifx_i2c_transport_layer.c"
	"${CMAKE_CURRENT_LIST_DIR}/optiga-trust-m/optiga/crypt/optiga_crypt.c"
	"${CMAKE_CURRENT_LIST_DIR}/optiga-trust-m/optiga/util/optiga_util.c")

set(COMPONENT_REQUIRES mbedtls)

register_component()

target_sources(mbedcrypto PRIVATE "${COMPONENT_SRCS}")
								
target_compile_definitions(mbedcrypto PUBLIC
    -DMBEDTLS_ECDH_GEN_PUBLIC_ALT
	-DMBEDTLS_ECDH_COMPUTE_SHARED_ALT
	-DMBEDTLS_ECDSA_VERIFY_ALT
	-DMBEDTLS_ECDSA_SIGN_ALT
	-DMBEDTLS_RSA_ALT
)

target_include_directories(mbedcrypto PUBLIC
  $<BUILD_INTERFACE:${COMPONENT_ADD_INCLUDEDIRS}>
)
