# Microsoft Azure IoT with </br> Infineon OPTIGA&trade; Trust M 

* [Introduction](#introduction)
* [Hardware](#Hardware)
* [Getting Started](#getting-started)
  * [Step 1. Downlaod and install missing components](#Step-1-Downlaod-and-install-missing-components )
  * [Step 2. Setting up Microsoft Azure IoT Hub](#Step-2-Setting-up-Microsoft-Azure-IoT-Hub)
  * [Step 3. Configuring and Building Sample](#Step-3-configuring-and-building-sample)
* [Troubleshooting](#troubleshooting)
* [Contributing](#Contributing)
* [License](#License)
* [Annex. Porting guide for mbedTLS](PortingGuide.md)

## Introduction

The ESP Azure OPTIGA™ Trust M package is based on Azure IoT C SDK and allows to connect Espressif ESP32 based devices to the Azure IoT hub using OPTIGA™ Trust M security chip for X.509 based security in Azure IoT hub. It provides some examples which can help to understand most common use cases.

## Hardware

  * [OPTIGA Trust M Shield2Go](https://www.infineon.com/cms/en/product/evaluation-boards/s2go-security-optiga-m/)
  * [ESP32-DevKitC](https://www.espressif.com/en/products/hardware/development-boards)
  <details>
	<summary>Connection example</summary>
	<img src="docs/images/Esp32_connection_with_Shield2Go.jpg" >
  </details>
  
This Application Note uses Espressif ESP32, but it also shows how to port onto another host platform. You can find more information [below](#porting-guide-to-enable-optiga-trust-m-on-your-mbedtls-package) 

## Getting Started

### Step 1. Downlaod and install missing components 

1. **ESP-IDF ver. 4.1** .ESP IDF stands for Espressif IoT Development Framework. The installation guidelines based on you setup can be found [here](ESP-IDF (Espressif IoT Development Framework)). Please try to build a sample ["Hello World"](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/index.html#step-5-start-a-project) project before continuing.

2. **This repository**
  ``` bash
  git clone --recursive https://github.com/Infineon/azure-optiga-trust-m
  ```

## Step 2. Setting up Microsoft Azure IoT Hub

### Create an IoT Hub using the Azure portal

- Create an account and get an [Azure subscription](https://azure.microsoft.com/en-in/free/?WT.mc_id=A261C142F) if you do not have an Azure subscription already.
- Create an Azure IoT Hub by following the documentation [here](https://docs.microsoft.com/en-us/azure/iot-hub/iot-hub-create-through-portal#create-an-iot-hub).

> **Note: When selecting the "Pricing and scale tier", there is also an option to select , F1: Free tier, which should be sufficient for basic evaluation.**

### Create a CA certificate for Azure IoT Hub

[This](https://docs.microsoft.com/en-us/azure/iot-hub/iot-hub-security-x509-get-started#get-x509-ca-certificates) section of the MS Azure IoT tutorial describes generic difference between different type of supported crednetials:
```
The X.509 certificate-based security in the IoT Hub requires you to start with an X.509 certificate chain, which includes the root certificate as well as any intermediate certificates up until the leaf certificate.

You may choose any of the following ways to get your certificates:

1. Purchase X.509 certificates from a root certificate authority (CA). This method is recommended for production environments.

2. Create your own X.509 certificates using a third-party tool such as OpenSSL. This technique is fine for test and development purposes. See Managing test CA certificates for samples and tutorials for information about generating test CA certificates using PowerShell or Bash. The rest of this tutorial uses test CA certificates generated by following the instructions in Managing test CA certificates for samples and tutorials.

3. Generate an X.509 intermediate CA certificate signed by an existing root CA certificate and upload it to the hub. Once the intermediate certificate is uploaded and verified, as instructed below, it can be used in the place of a root CA certificate mentioned below. Tools like OpenSSL (openssl req and openssl ca) can be used to generate and sign an intermediate CA certificate.
```
The OPTIGA Trust M board comes with a [pre-provisioned unique X.509 certificate](https://github.com/Infineon/optiga-trust-m/tree/master/certificates), which correspond to the first option, but for testing we advice to provision a new test X.509 certificate **to the secure element** uwing a third-party tool such as OpenSSL.

For this please follow first **three** steps from the [guidance below](https://github.com/Azure/azure-iot-sdk-c/blob/master/tools/CACertificates/CACertificateOverview.md), namelly "Step 1 - Initial Setup", and "Step 2 - Create the certificate chain", and "Step 3 - Proof of Possession".

Now it becomes possible to provision your device with a new X.509 certificate and create a new Azure IoT Device.

### Creating a test X.509 device certificate

- Go to windows start menu and Open ESP-IDF command prompt

    <details><summary>Sample output</summary>
    ```bash
    Setting IDF_PATH: C:\Users\username\Desktop\esp-idf
    
    Adding ESP-IDF tools to PATH...
        C:\Users\username\.espressif\tools\xtensa-esp32-elf\esp-2019r2-8.2.0\xtensa-esp32-elf\bin
        C:\Users\username\.espressif\tools\esp32ulp-elf\2.28.51.20170517\esp32ulp-elf-binutils\bin
        C:\Users\username\.espressif\tools\cmake\3.13.4\bin
        C:\Users\username\.espressif\tools\openocd-esp32\v0.10.0-esp32-20190313\openocd-esp32\bin
        C:\Users\username\.espressif\tools\mconf\v4.6.0.0-idf-20190628\
        C:\Users\username\.espressif\tools\ninja\1.9.0\
        C:\Users\username\.espressif\tools\idf-exe\1.0.1\
        C:\Users\username\.espressif\tools\ccache\3.7\
        C:\Users\username\.espressif\python_env\idf4.0_py3.7_env\Scripts
        C:\Users\username\Desktop\esp-idf\tools
    
    Checking if Python packages are up to date...
    Python requirements from C:\Users\username\Desktop\esp-idf\requirements.txt are satisfied.
    
    Done! You can now compile ESP-IDF projects.
    Go to the project directory and run:
    
    idf.py build
    
    
    C:\Users\username\Desktop\esp-idf>
    ```
    </details>
- Change working directory to <azure-optiga-trust-m\examples\provision_test_certificate>
- Configure "Example Configuration" using below command

    ```sh
    idf.py menuconfig
    ```
- Build Personalisation project and Flash ESP32 using below command 
    ```bash	
    idf.py build
    idf.py -p <ESP32 serial port> flash
        E.g.: idf.py -p com7 flash

    //Custom build folder
    idf.py -B <CUSTOM_BUILD_FOLDER_PATH> build    
    idf.py -B <CUSTOM_BUILD_FOLDER_PATH> -p <ESP32 serial port> flash
    E.g. : idf.py -B c:\esp-build build
         : idf.py -B c:\esp-build -p com7 flash
    ```
- Once sample project is flashed successfully, you can monitor communication between ESP32 using
    ```sh
    idf.py monitor
    ```

* Public Key Extraction
  The demo project starts with generating a new keypair, where the private part stays on the secure element, and the public component   is printed out. You should be able to see something like this
  ```bash
  Device public key:
  -----BEGIN PUBLIC KEY-----
  MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzWVpzrgbuR5yM5/oz2DvD5+0czOs
  bxkYE2mZP6DCk1+uCPEa0EG3NFznRhBGIo5aX9eH1XHcsk6NdbMlhuLMDA==
  -----END PUBLIC KEY-----
  ```
  Copy the lines of key into a file called `device_public_key.pem`.
* Public Key Infrastructure Setup
  If you have completed [this](#Create-a-CA-certificate-for-Azure-IoT-Hub) step, you should have either `.\RootCA.pem` in Windows or `./certs/azure-iot-test-only.root.ca.cert.pem` in Bash.
  Now type in the following command using OpenSSL:
  ```bash
  openssl genrsa -out tempCsrSigner.key 2048
  openssl req -new -key tempCsrSigner.key -out deviceCert.csr
  ```
  For Bash
  ```bash
  openssl x509 -req -in deviceCert.csr -CA ./certs/azure-iot-test-only.root.ca.cert.pem -CAkey ./private/azure-iot-test-only.root.ca.cert.pem -CAcreateserial -out deviceCert.pem -days 500 -sha256 -force_pubkey device_public_key.pem 
  ```
  For Powershell
  ```bash
  openssl x509 -req -in deviceCert.csr -CA .\certs\azure-iot-test-only.root.ca.cert.pem -CAkey .\private\azure-iot-test-only.root.ca.cert.pem -CAcreateserial -out deviceCert.pem -days 500 -sha256 -force_pubkey device_public_key.pem
  ```
* Writing back the new certificate
### Creating a new Azure IoT Device

- Create an Azure IoT Hub by following steps under section **Create an X.509 device for your IoT hub** from the documentation [here](https://docs.microsoft.com/en-us/azure/iot-hub/iot-hub-security-x509-get-started#create-an-x509-device-for-your-iot-hub).
- Note down newly created IoT Device **Device ID** 


## Step 3. Configuring and Building Sample

- Open the file **"optiga_lib_config.h"** present in the below given path and update the value of macro **"OPTIGA_COMMS_DEFAULT_RESET_TYPE"** to **"1"** 
    ```sh
    File path : azure-optiga-trust-m\components\optiga\optiga-trust-m\optiga\include\optiga
    ```
- Follow this step only if Server root CA need to be loaded into any of OPTIGA data object.This certficate will be used for Authentication in TLS session. 
    - Comment the macro **-DMBEDTLS_RSA_ALT** from the Cmakelist.txt file present in the path <azure-optiga-trust-m\components\optiga> as shown below
        ```sh
        #-DMBEDTLS_RSA_ALT
        ```
        >Note: Since OPTIGA™ Trust M supports only RSA 1024/2048 and Azure Certificate chain has RSA 4096 certificate, the certificate path validation cannot be performed using OPTIGA™ Trust M RSA feature. Hence usage of RSA feature from OPTIGA™ Trust M need to be disabled. 
    - Enable the macro **SET_TRUSTED_CERT_IN_SAMPLES** and **LOAD_TA_FROM_OPTIGA** from the Cmakelist.txt file present in the path <azure-optiga-trust-m2\examples\iothub_client_sample_mqtt\main> by uncommenting the compile time definitions as below.
        ```sh
        component_compile_definitions(SET_TRUSTED_CERT_IN_SAMPLES)
        component_compile_definitions(LOAD_TA_FROM_OPTIGA)
        ```
    - To enable server certficate validation using OPTIGA, the region specific server root CA certificate must be loaded in any of OPTIGA data object either by personalization or by writing to object using OPTIGA write API
    - To load trust anchor using OPTIGA write API, modify file <azure-optiga-trust-m\components\optiga\optiga-trust-m\examples\utilities\optiga_trust.c> as below
        - User can choose the root CA as either from the below available certificate or can provide specific certificate by setting value as "1". E.g.:  #if 1
        By default user can select the **DigiCert Baltimore Root** certificate as it is used Globally as Root Server CA.
        <details>
        <summary>Code fragment </summary>
            
	    ```c
            static void write_optiga_trust_anchor(void)
            {
            #if 0
            	/* DigiCert Baltimore Root --Used Globally--*/
            	// This cert should be used when connecting to Azure IoT on the Azure Cloud available globally. 
            	const uint8_t trust_anchor[] = {
            		                            //contains Baltimore certificate data 
            	                               };
            	   write_data_object(OPTIGA_TA, trust_anchor, sizeof(trust_anchor));
            #endif //Baltimore
            
            #if 0
            	/* DigiCert Global Root CA */
            	// This cert should be used when connecting to Azure IoT on the https://portal.azure.cn Cloud address.
            	
            	const uint8_t trust_anchor[] = {
            		                            //contains DigiCert Global Root CA
            	                               };
            	   write_data_object(OPTIGA_TA, trust_anchor, sizeof(trust_anchor));
            #endif //DigiCert Global Root CA
            
            #if 0
            	/* D-TRUST Root Class 3 CA 2 2009 */
            	// This cert should be used when connecting to Azure IoT on the https://portal.microsoftazure.de Cloud address.
            	
            	const uint8_t trust_anchor[] = {
            		                            //D-TRUST Root Class 3 CA
            	                               };
            	   write_data_object(OPTIGA_TA, trust_anchor, sizeof(trust_anchor));
            #endif //D-TRUST Root Class 3 CA 2 2009
            
            #if 0
    	    /* User can provide a specific server certificate here and can load in any data object of optiga */
        
        	const uint8_t trust_anchor[] = = {
            		                      //place to provide region specific server root CA certificate  
            	                           };
                   write_data_object(OPTIGA_TA, trust_anchor, sizeof(trust_anchor));
            #endif //Region Specific Certificate 
            
            }
            ```
            
	    </details>
	    
    - Uncomment **write_optiga_trust_anchor** in API "optiga_trust_init(void)" as below:
        ```sh
        //The below specified functions can be used to personalize OPTIGA w.r.t
        //certificates, Trust Anchors, etc.
    
        //write_device_certificate ();
        //write_set_high_performance();  //setting current limitation to 15mA
        //write_platform_binding_secret ();  
        //read_certificate ();
        write_optiga_trust_anchor();  //can be used to write server root certificate to optiga data object  
        ```

- Go to windows start menu and Open ESP-IDF command prompt

    <details>
	<summary>Sample output</summary>
    
    ```bash
    Setting IDF_PATH: C:\Users\username\Desktop\esp-idf
    
    Adding ESP-IDF tools to PATH...
        C:\Users\username\.espressif\tools\xtensa-esp32-elf\esp-2019r2-8.2.0\xtensa-esp32-elf\bin
        C:\Users\username\.espressif\tools\esp32ulp-elf\2.28.51.20170517\esp32ulp-elf-binutils\bin
        C:\Users\username\.espressif\tools\cmake\3.13.4\bin
        C:\Users\username\.espressif\tools\openocd-esp32\v0.10.0-esp32-20190313\openocd-esp32\bin
        C:\Users\username\.espressif\tools\mconf\v4.6.0.0-idf-20190628\
        C:\Users\username\.espressif\tools\ninja\1.9.0\
        C:\Users\username\.espressif\tools\idf-exe\1.0.1\
        C:\Users\username\.espressif\tools\ccache\3.7\
        C:\Users\username\.espressif\python_env\idf4.0_py3.7_env\Scripts
        C:\Users\username\Desktop\esp-idf\tools
    
    Checking if Python packages are up to date...
    Python requirements from C:\Users\username\Desktop\esp-idf\requirements.txt are satisfied.
    
    Done! You can now compile ESP-IDF projects.
    Go to the project directory and run:
    
    idf.py build
    
    
    C:\Users\username\Desktop\esp-idf>
    ```
    </details>
- Change working directory to <azure-optiga-trust-m\examples\iothub_client_sample_mqtt>
- Configure "Example Configuration" and "OPTIGA(TM) Trust M config" using below command

    ```sh
    idf.py menuconfig
    ```
    ![](docs/images/menu_config_1.png)

- Select Example Configuration and update WiFi SSID, WiFi Password and IoT Hub device connection string

- To get IoT Hub Device Connection String: 
    - navigate to your IoT Hub, and then select Setting > shared Access policies > iothubowner
    - Under shared access keys, copy connection string – primary key E.g.: "HostName=**IoT_hub_name.azure-devices.net**;SharedAccessKeyName=iothubowner;SharedAccessKey=id9ublohj/CdVFb5jLS/9bF3hAfqE2TRpb4woDhlciM="
    - Update Host name from the above step and device id noted down during Azure IoT device creation in the below connection string
    ```bash 
    "HostName=**your_IoT_hub_name.azure-devices.net**;DeviceId=**Azure_Device_ID**;x509=true"
    ```
    - Update the above connection string as IoT Hub Device Connection String in the Example Configuration and save the configuration

    ![](docs/images/menu_config_2.png)

- Go back to the main page of menuconfig and select "OPTIGA(TM) Trust M config" option and update the below parameters:

    ![](docs/images/menu_config_3.png)
    
    - Select the certificate Slot out of 4 slots provided, where the device certificate is personalized
    - Select the Private Key slot out of 4 slots provided, where the device private key is personalized
    - Select the Trust Anchor slot out of 3 slots provided, where the Azure trust anchor is personalized 

    ![](docs/images/menu_config_4.png)

- Build Sample project and Flash ESP32 using below command 
    ```bash	
    idf.py build
    idf.py -p <ESP32 serial port> flash
        E.g.: idf.py -p com7 flash

    //Custom build folder
    idf.py -B <CUSTOM_BUILD_FOLDER> build    
    idf.py -B <CUSTOM_BUILD_FOLDER> -p <ESP32 serial port> flash
    E.g. : idf.py -B c:\esp-build build
         : idf.py -B c:\esp-build -p com7 flash
    ```
> Note: During Sample project build, if you get an error as **ccache error : Failed to create temprorary file** then this is due to file path length restriction to 260 characters. To avoid this error, clone the Azure OPTIGA Trust M to the top level directory such as in C or D drive or use custom build folder as the top level directory as mentioned in above step
- Once sample project is flashed successfully, you can monitor communication between ESP32 and your azure IoT Hub device using
    ```sh
    idf.py monitor
    ```
    ![](docs/images/idf_monitor.png)
    
- To monitor events on Azure cloud, navigate to Cloud shell on azure portal and execute below commands
    ```sh
    az extension add --name azure-cli-iot-ext 
   az iot hub monitor-events -n <your IoT Hub Name>
    ```
    
    ![](docs/images/Azure_cloudshell_monitor.png)
   
   
- To send message from Azure cloud to ESP32 during active communication:
    ```sh
      az iot device c2d-message send -d Iot Device name -n IoT-Hub name --data "message"
    ```
## Troubleshooting
<a name="troubleshooting"></a>

1. Some common problems can be fixed by disabling the firewall.

2. You can try with the followings, if your build fails:
	- `git submodule update --init --recursive`
	- Check the compiler version and verify that it is the correct one for your ESP IDF version.
	- Check if the IDF_PATH is set correctly
	- Clean the project with “idf.py fullclean” or for custom build with “idf.py -B <CUSTOM_BUILD_FOLDER_PATH> fullclean”
3. Ensure that the device connection string received from Azure IoT Hub are correct.

## Contributing
Please read [CONTRIBUTING.md](https://github.com/Infineon/arduino-optiga-trust-x/blob/master/CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests to us.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

