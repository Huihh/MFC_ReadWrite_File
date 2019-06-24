#ifndef __DEVICE_DRIVE_METH_H__
#define __DEVICE_DRIVE_METH_H__


#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned char	U8;
typedef unsigned long	U32;
#ifdef _WIN32
typedef void*			HDEV;
#define CCAPI			__stdcall
#else
typedef int				HDEV;
#define CCAPI
#endif

/************************************* IMPORTANT **************************************
 * These functions are NOT thread safe, so if there are more than one thread need to  *
 * write and read the same device, the threads MUST be synchronized and if one thread *
 * have written the command data to device but have NOT read the response, the other  *
 * threads should NOT write or read the device, otherwise, the response data will be  *
 * incorrect.																		  *
 **************************************************************************************/

/* Check the device whether that is a recognized device.
 * This function should be implemented by the user.
 * In this function just use the function TWriteDeviceData and TReadDeviceData to write
 * command to device and get response from device to check if it is a recognized device.
 */
typedef U32 (*TCheckDevice)(HDEV hDevice);


/* Set interface file name
 * Parameters
 * szInterface	 
 *		The interface file name.
 * Return Values 
 *		If the function succeeds, the return value is DR_SUCCESS. If the function fails, 
 *		it return nonzero.
 * Remarks
 *		Call this function first before all others.
 */
typedef U32 (*TSetInterfaceNameA)(const char* szInterface);
#ifdef _WIN32
typedef U32 (*TSetInterfaceNameW)(const wchar_t* szInterface);
#endif

/* Open device using device name. 
 * Parameters
 * szDevName	
 *		The device name.
 * pFnCheck		
 *		Callback function for check device. if it is NULL, any device have a file whose
 *		name is match with the szInterface will be recognized as a valid device, else 
 *		the callback function will check the device.
 * phDevice		
 *		if open device is successful, the device HDEV is returned in this parameter.
 * Return Values 
 *		If the function succeeds, the return value is DR_SUCCESS. If the function fails,
 *		it return nonzero.
 */
typedef U32 (*TOpenDeviceA)(const char* szDevName, TCheckDevice pFnCheck, HDEV* phDevice);
#ifdef _WIN32
typedef U32 (*TOpenDeviceW)(const wchar_t* szDevName, TCheckDevice pFnCheck, HDEV* phDevice);
#endif

/* Close device.
 * Parameters
 * hDevice		
 *		The opened device HDEV which want to close.
 * Return Values 
 *		If the function succeeds, the return value is DR_SUCCESS. If the function fails,
 *		it return nonzero.
 */
typedef U32 (*TCloseDevice)(HDEV hDevice);

/* Read data from device. 
 * Parameters
 * hDevice		
 *		The device HDEV opened with TOpenDevice.
 * pbData		
 *		The data buffer for saving read data, 4K is recommended for its length.
 * pulData		
 *		On input it is the length want to read from device. It MUST be no more than 4K.
 *		if the function succeeds, it is the length of data have read from the device.
 * Return Values 
 *		If the function succeeds, the return value is DR_SUCCESS. If the function fails,
 *		it return nonzero.
 */
typedef U32 (*TReadDeviceData)(HDEV hDevice,U8* pbData,U32* pulData);

/* Write data to device. 
 * Parameters
 * hDevice		
 *		The device HDEV opened with TOpenDevice.
 * pbData		
 *		The data to be written to the device. 
 * ulData		
 *		The length of pbData, it MUST be no more than 4K.
 * Return Values 
 *		If the function succeeds, the return value is DR_SUCCESS. If the function fails,
 *		it return nonzero.
 * Remarks
 *		This operation MUST be followed with TReadDeviceData.
 */
typedef U32 (*TWriteDeviceData)(HDEV hDevice,const U8* pbData,U32 ulData);

/* Enumerate devices. 
 * Parameters
 * szDevices	
 *		On input, it is a NULL TCHAR pointer, when it returned, it point to a buffer 
 *		for saving the device names. it use NULL to separate device names and double 
 *		NULL for ending.
 * pulLen		
 *		On input, it can be any length, when it returned, it is the length of szDevices 
 *		including the double NULL. 
 * Return Values 
 *		If there are any recognized device is found, it success and return DR_SUCCESS,
 *		else it return nonzero.
 * Remarks 
 *		When the szDevices is NOT needed, it should be freed by using function 
 *		TFreeDevName.
 */
typedef U32 (*TEnumDeviceA)(char** szDevices,U32 *pulLen,TCheckDevice pFnCheck);
#ifdef _WIN32
typedef U32 (*TEnumDeviceW)(wchar_t** szDevices,U32 *pulLen,TCheckDevice pFnCheck);
#endif

/* Free device names. 
 * Parameters
 * pData	
 *		The pointer which point to the device names returned by function TEnumDevice.
 */
typedef void (*TFreeDevName)(void* pData);

typedef struct device_drive_metha_st
{
	TSetInterfaceNameA	SetInterfaceName;
	TOpenDeviceA		OpenDevice;
	TCloseDevice		CloseDevice;
	TReadDeviceData		ReadDeviceData;
	TWriteDeviceData	WriteDeviceData;
	TEnumDeviceA		EnumDevice;
	TFreeDevName		FreeDevName;
}DRIVE_METHA,*PDRIVE_METHA;

#ifdef _WIN32
typedef struct device_drive_methw_st
{
	TSetInterfaceNameW	SetInterfaceName;
	TOpenDeviceW		OpenDevice;
	TCloseDevice		CloseDevice;
	TReadDeviceData		ReadDeviceData;
	TWriteDeviceData	WriteDeviceData;
	TEnumDeviceW		EnumDevice;
	TFreeDevName		FreeDevName;
}DRIVE_METHW,*PDRIVE_METHW;
#endif

/* These method functions will return the values defined following or other values 
 * defined by windows. 
 */

/* operation success */
#define DR_SUCCESS					0		

/* memory error */	
#define DR_MEMORY_HOST				0xE000A001  

/* no device found when enumerating device */ 
#define DR_NO_DEVICE_FOUND			0xE000A002	

/* the device is still calculating when reading data from device. if this error 
 * retrieved, read again after a while. As to attain a better performance(such as
 * RSA, DES or SM1), it is strong recommended that waiting a while(the waiting time 
 * should be decided according to the command) between writing data to device and
 * reading data from device.
 */
#define DR_RD_BUSY					0xE000A003	  

/* the data read from device can NOT be recognized, that is the response data may 
 * have been read by other program or system. if this error retrieved, rewrite the
 * data and read again is recommended.
 */
#define DR_RD_DATA					0xE000A004	

/* read/write data length error. the data length is more than 4K.
 */
#define DR_DATA_LEN					0xE000A005  

/* function not support */
#define DR_NOT_SUPPORT				0xE000A006

/* Get windows drive method for card.
 * Parameters
 * pMeth	
 *		The method pointer. When the function returned, it contained the drive method.
 * ulDriveType		
 *		The driver type, Now the ulDriveType MUST be 0.
 * Return Values 
 *		If the function succeeds, the return value is DR_SUCCESS else it is -1.
 */
U32 CCAPI CC_GetDriveMethA(PDRIVE_METHA* pMeth, U32 ulDriveType);
#ifdef _WIN32
U32 CCAPI CC_GetDriveMethW(PDRIVE_METHW* pMeth, U32 ulDriveType);

#ifdef WINCE
/* There is only unicode version is supported, if using an ascii version in wince the 
 * DR_NOT_SUPPORT will be returned */
#define DRIVE_METH DRIVE_METHW
#define PDRIVE_METH PDRIVE_METHW
#define CC_GetDriveMeth CC_GetDriveMethW
#else
#ifndef UNICODE
#define DRIVE_METH DRIVE_METHA
#define PDRIVE_METH PDRIVE_METHA
#define CC_GetDriveMeth CC_GetDriveMethA
#else
#define DRIVE_METH DRIVE_METHW
#define PDRIVE_METH PDRIVE_METHW
#define CC_GetDriveMeth CC_GetDriveMethW
#endif
#endif

#else
#define DRIVE_METH DRIVE_METHA
#define PDRIVE_METH PDRIVE_METHA
#define CC_GetDriveMeth CC_GetDriveMethA
#endif

#ifdef __cplusplus
}
#endif

#endif /*__DEVICE_DRIVE_METH_H__*/