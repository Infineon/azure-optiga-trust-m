#
# Component Makefile
#
COMPONENT_ADD_INCLUDEDIRS := optiga-trust-m/optiga/include

COMPONENT_SRCDIRS := optiga-trust-m/pal/esp32_freertos \
                     optiga-trust-m/optiga/cmd \
                     optiga-trust-m/optiga/common \
                     optiga-trust-m/optiga/comms/ifx_i2c \
                     optiga-trust-m/optiga/comms \
                     optiga-trust-m/optiga/crypt \
                     optiga-trust-m/optiga/util \
                     optiga-trust-m/examples\integration \
					 optiga-trust-m/optiga \

COMPONENT_SUBMODULES += mbedtls
