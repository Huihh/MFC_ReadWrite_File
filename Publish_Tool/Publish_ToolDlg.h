
// Publish_ToolDlg.h : 头文件
//

#pragma once

#include "Winscard.h"
#include "afxwin.h"


#include "Dev_drive.h"


// CPublish_ToolDlg 对话框
class CPublish_ToolDlg : public CDialogEx
{
// 构造
public:
	CPublish_ToolDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_PUBLISH_TOOL_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CComboBox m_mPort;
	CRichEditCtrl m_mResult;
	afx_msg void OnClickedButtonRefreshReader();
	afx_msg void OnClickedButtonOpenClose();
	afx_msg void OnBnClickedButtonClear();
	afx_msg void OnBnClickedButtonExecute();

public:
	SCARDCONTEXT	hContext;
	SCARDHANDLE		hCard;

	DWORD			dwRetCode;


	CHAR			ReaderBuf[1024];  
	DWORD			ReaderBufLen;

	CHAR			ATRBuf[256];
	DWORD			ATRBufLen;


	DWORD			AProtocol;
	DWORD			dwProtocol;
	DWORD			dwState;

	CStringArray	ArrayReaderList;
	CString			PCSCReaderName;




	//保存GP PutKey指令计算明文      by Huihh 2017.08.17
	BYTE SessionKey_ENC[16];
	BYTE SessionKey_MAC[16];
	BYTE SessionKey_DEK[16];






	void DisplayReaders();
	void ShowMessageString(CString Message);
	void ShowMessageStringAlert(CString Message, int color);
	INT ResetCard(INT DisplayFlag = 1);            //添加显示Flag 用于是否显示指令流   0: 不显示, 1:显示   其它暂未使用,   默认为1            by Huihh 2017.12.26 

	BOOL GPProcess(void);
	BOOL ExAuthen(CString sKey);
	void CPublish_ToolDlg::CstringToByte(CString sInput, BYTE bOutput[]);

	

	int TransmitData_PCSC(BYTE SendBuf[], int SendLen, BYTE RecvBuf[], unsigned long *RecvLen);
	CString SendCommandGetValueOrSW(CString sCmd, int Flag);
	BOOL AsciiToHex(BYTE pAsciiArray[], BYTE pHexArray[], int Len);


	CWinThread		*pWinThread;

	static UINT Thread_Execute(LPVOID pPram);
	int Process_Execute(LPVOID pPram);


	BOOL TerminateThreadExecute(CWinThread *pWinThread);

	void StringToHex(CString str, BYTE buf[], UINT *len);
	void ShowMessageBuf(BYTE buf[], UINT len);
	UINT CheckAESParaLegal(UINT type, CString str);





	//fs
	void SKF_CREATE_FILE();
	void SKF_CREATE_MF();
	void SKF_CREATE_DF0();
	void SKF_CREATE_DF1();
	void SKF_CREATE_DF2();
	void SKF_CREATE_EF0();
	void SKF_CREATE_EF1();
	void SKF_CREATE_EF2();
	void SKF_DELET_FILE();
	void SKF_DELET_DF0();
	void SKF_DELET_DF1();
	void SKF_DELET_DF2();
	void SKF_DELET_EF0();
	void SKF_DELET_EF1();
	void SKF_DELET_EF2();
	void SKF_SELECT_FILE();
	void SKF_SELECT_MF();
	void SKF_SELECT_DF0();
	void SKF_SELECT_EF0();
	void SKF_READ_FILE();
	void SKF_WRITE_FILE();
	void SKF_GET_DF_LIST();
	void SKF_GET_EF_LIST();
	void SKF_GET_DEV_INFO();
	void SKF_SET_DEV_INFO();
	void SKF_GET_FILE_INFO();
	void SKF_GET_APP_INFO();



	void SKF_GET_RAND();
	void SKF_DEVICE_AUTH();
	void SKF_MODIFY_DEV_AUTH_KEY();
	void SKF_ACTIVATE_COS();
	void SKF_MODIFY_PIN();
	void SKF_VERIFY_SOPIN();
	void SKF_VERIFY_PIN();
	void SKF_UNLOCK_RESET_PIN();
	void SKF_GET_SESSION_KEY();
	void SKF_GENARATE_RSA_KEY_PAIR();
	void SKF_GENARATE_SM2_KEY_PAIR();
	void SKF_EXPORT_PSA_PUB_KEY();
	void SKF_EXPORT_SM2_PUB_KEY();
	void SKF_IMPORT_PUBKEY();
	void SKF_IMPORT_KEY();
	void SKF_DELET_KEY();
	void SKF_SESSION_KEY_ALG();
	void SKF_SET_MODE();
	void SKF_SYM_MAC();
	void SKF_SYM_ENCRYPT();
	void SKF_SYM_SET_KEY_RSA();
	void SKF_SYM_DECRYPT();
	void SKF_HASH_SM3();
	void SKF_SM2_SIGN();
	void SKF_SM2_VERTFY();



	//test case
	void SKF_Functional_Testing_Case_1();
	void SKF_Functional_Testing_Case_2();
	void SKF_Functional_Testing_Case_3();
	void SKF_Functional_Testing_Case_4();
	void SKF_Functional_Testing_Case_5();
	void SKF_Functional_Testing_Case_6();
	void SKF_Functional_Testing_Case_7();
	void SKF_Functional_Testing_Case_8();
	void SKF_Functional_Testing_Case_9();
	void SKF_Functional_Testing_Case_10();
	void SKF_Functional_Testing_Case_11();
	void SKF_Functional_Testing_Case_12();
	void SKF_Functional_Testing_Case_13();
	void SKF_Functional_Testing_Case_14();
	void SKF_Functional_Testing_Case_15();
	void SKF_Functional_Testing_Case_16();
	void SKF_Functional_Testing_Case_17();
	void SKF_Functional_Testing_Case_18();
	void SKF_Functional_Testing_Case_19();
	void SKF_Functional_Testing_Case_20();
	void SKF_Functional_Testing_Case_21();
	void SKF_Functional_Testing_Case_22();
	void SKF_Functional_Testing_Case_23();
	void SKF_Functional_Testing_Case_24();
	void SKF_Functional_Testing_Case_25();
	void SKF_Functional_Testing_Case_26();
	void SKF_Functional_Testing_Case_27();
	void SKF_Functional_Testing_Case_28();
	void SKF_Functional_Testing_Case_29();
	void SKF_Functional_Testing_Case_30();
	void SKF_Functional_Testing_Case_31();
	void SKF_Functional_Testing_Case_32();
	void SKF_Functional_Testing_Case_33();
	void SKF_Functional_Testing_Case_34();
	void SKF_Functional_Testing_Case_35();
	void SKF_Functional_Testing_Case_36();
	void SKF_Functional_Testing_Case_37();
	void SKF_Functional_Testing_Case_38();
	void SKF_Functional_Testing_Case_39();
	void SKF_Functional_Testing_Case_40();
	void SKF_Functional_Testing_Case_41();
	void SKF_Functional_Testing_Case_42();
	void SKF_Functional_Testing_Case_43();
	void SKF_Functional_Testing_Case_44();
	void SKF_Functional_Testing_Case_45();
	void SKF_Functional_Testing_Case_46();
	void SKF_Functional_Testing_Case_47();
	void SKF_Functional_Testing_Case_48();
	void SKF_Functional_Testing_Case_49();
	void SKF_Functional_Testing_Case_50();
	void SKF_Functional_Testing_Case_51();
	void SKF_Functional_Testing_Case_52();
	void SKF_Functional_Testing_Case_53();
	void SKF_Functional_Testing_Case_54();
	void SKF_Functional_Testing_Case_55();
	void SKF_Functional_Testing_Case_56();
	void SKF_Functional_Testing_Case_57();
	void SKF_Functional_Testing_Case_58();
	void SKF_Functional_Testing_Case_59();
	void SKF_Functional_Testing_Case_60();
	void SKF_Functional_Testing_Case_61();
	void SKF_Functional_Testing_Case_62();
	void SKF_Functional_Testing_Case_63();
	void SKF_Functional_Testing_Case_64();
	void SKF_Functional_Testing_Case_65();
	void SKF_Functional_Testing_Case_66();
	void SKF_Functional_Testing_Case_67();
	void SKF_Functional_Testing_Case_68();
	void SKF_Functional_Testing_Case_69();
	void SKF_Functional_Testing_Case_70();
	void SKF_Functional_Testing_Case_71();
	void SKF_Functional_Testing_Case_72();
	void SKF_Functional_Testing_Case_73();
	void SKF_Functional_Testing_Case_74();
	void SKF_Functional_Testing_Case_75();
	void SKF_Functional_Testing_Case_76();
	void SKF_Functional_Testing_Case_77();
	void SKF_Functional_Testing_Case_78();
	void SKF_Functional_Testing_Case_79();
	void SKF_Functional_Testing_Case_80();
	void SKF_Functional_Testing_Case_81();
	void SKF_Functional_Testing_Case_82();
	void SKF_Functional_Testing_Case_83();
	void SKF_Functional_Testing_Case_84();
	void SKF_Functional_Testing_Case_85();
	void SKF_Functional_Testing_Case_86();
	void SKF_Functional_Testing_Case_87();
	void SKF_Functional_Testing_Case_88();
	void SKF_Functional_Testing_Case_89();
	void SKF_Functional_Testing_Case_90();
	void SKF_Functional_Testing_Case_91();
	void SKF_Functional_Testing_Case_92();
	void SKF_Functional_Testing_Case_93();
	void SKF_Functional_Testing_Case_94();
	void SKF_Functional_Testing_Case_95();
	void SKF_Functional_Testing_Case_96();
	void SKF_Functional_Testing_Case_97();
	void SKF_Functional_Testing_Case_98();
	void SKF_Functional_Testing_Case_99();
	void SKF_Functional_Testing_Case_100();
	void SKF_Functional_Testing_Case_101();
	void SKF_Functional_Testing_Case_102();
	void SKF_Functional_Testing_Case_103();
	void SKF_Functional_Testing_Case_104();
	void SKF_Functional_Testing_Case_105();
	void SKF_Functional_Testing_Case_106();
	void SKF_Functional_Testing_Case_107();
	void SKF_Functional_Testing_Case_108();

	void SKF_Functional_Testing_ShowResult(int i);
	void SKF_Functional_Testing_Done();

	void SKF_Functional_Testing();


	void SKF_Police_Testing_Case_1();
	void SKF_Police_Testing_Case_2();
	void SKF_Police_Testing_Case_3();
	void SKF_Police_Testing_Case_4();
	void SKF_Police_Testing_Case_5();
	void SKF_Police_Testing_Case_6();

	void SKF_Police_Testing_ShowResult(int i);
	void SKF_Police_Testing_Done();


public:
	CButton m_mCreateFile;
	CButton m_mDeleteFile;


	CButton m_mSelectFile;
	CButton m_mReadFile;
	CButton m_mWriteFile;
	CButton m_mGetFileList;
	CButton m_mGetDevInfo;
	CButton m_mSetDevInfo;

	CButton m_mGetRand;
	CButton m_mDeviceAuth;
	CButton m_mModifyPin;
	CButton m_mGetSessionKey;

	CButton m_mVerifyPin;
	CButton m_mUnBlockResetPin;

	CButton m_mImportPubKey;
	CButton m_mImportKey;
	CButton m_mDeletKey;
	CButton m_mSessionKeyAlg;
	CButton m_mSetMode;
	CButton m_mSymMac;
	CButton m_mSymEncrypt;
	CButton m_mSymDecrypt;

	afx_msg void OnBnClickedButtonFsSelectAll();
	afx_msg void OnBnClickedButtonBusnissSelectAll();
	afx_msg void OnBnClickedButtonIkiselectAll();
	CEdit m_mSingleCmd;
	afx_msg void OnBnClickedButtonSendCmd();

	CEdit m_mCurrentState;
	afx_msg void OnBnClickedButtonGetCurrentState();
	afx_msg void OnBnClickedButtonSetState();
	CComboBox m_mSetState;
	CButton m_mModDevAutKey;
	CButton m_mGetAppList;
	CButton m_mGetSM2Key;
	CButton m_mGetRSAKey;
	CButton m_mGenRSAKey;
	CButton m_mGenSM2Key;
	CButton m_mSM3Hash;
	CButton m_mSM2Sign;
	CButton m_mSM2Vertfy;
	CButton m_mCreateDF1;
	CButton m_mCreateEF1;
	CButton m_mSelectDF1;
	CButton m_mSelectEF1;
	CButton m_mSelectMF;
	CButton m_mCreateMF;
	
	CButton m_mCase1;
	CButton m_mCase2;
	CButton m_mCase3;
	CButton m_mCase4;
	CButton m_mCase5;
	CButton m_mCase6;
	CButton m_mCase7;
	CButton m_mCase8;
	CButton m_mCase9;
	CButton m_mCase10;
	CButton m_mCase11;
	CButton m_mCase12;
	CButton m_mCase13;
	CButton m_mCase14;
	CButton m_mCase15;
	CButton m_mCase16;
	CButton m_mCase17;
	CButton m_mCase18;
	CButton m_mCase19;
	CButton m_mCase20;
	CButton m_mCase21;
	CButton m_mCase22;
	CButton m_mCase23;
	CButton m_mCase24;
	CButton m_mCase25;
	CButton m_mCase26;
	CButton m_mCase27;
	CButton m_mCase28;
	CButton m_mCase29;
	CButton m_mCase30;
	CButton m_mCase31;
	CButton m_mCase32;
	CButton m_mCase33;
	CButton m_mCase34;
	CButton m_mCase35;
	CButton m_mCase36;
	CButton m_mCase37;
	CButton m_mCase38;
	CButton m_mCase39;
	CButton m_mCase40;
	CButton m_mCase41;
	CButton m_mCase42;
	CButton m_mCase43;
	CButton m_mCase44;
	CButton m_mCase45;
	CButton m_mCase46;
	CButton m_mCase47;
	CButton m_mCase48;
	CButton m_mCase49;
	CButton m_mCase50;
	CButton m_mCase51;
	CButton m_mCase52;
	CButton m_mCase53;
	CButton m_mCase54;
	CButton m_mCase55;
	CButton m_mCase56;
	CButton m_mCase57;
	CButton m_mCase58;
	CButton m_mCase59;
	CButton m_mCase60;
	CButton m_mCase61;
	CButton m_mCase62;
	CButton m_mCase63;
	CButton m_mCase64;
	CButton m_mCase65;
	CButton m_mCase66;
	CButton m_mCase67;
	CButton m_mCase68;
	CButton m_mCase69;
	CButton m_mCase70;
	CButton m_mCase71;
	CButton m_mCase72;
	CButton m_mCase73;
	CButton m_mCase74;
	CButton m_mCase75;
	CButton m_mCase76;
	CButton m_mCase77;
	CButton m_mCase78;
	CButton m_mCase79;
	CButton m_mCase80;
	CButton m_mCase81;
	CButton m_mCase82;
	CButton m_mCase83;
	CButton m_mCase84;
	CButton m_mCase85;
	CButton m_mCase86;
	CButton m_mCase87;
	CButton m_mCase88;
	CButton m_mCase89;
	CButton m_mCase90;
	CButton m_mCase91;
	CButton m_mCase92;
	CButton m_mCase93;
	CButton m_mCase94;
	CButton m_mCase95;
	CButton m_mCase96;
	CButton m_mCase97;
	CButton m_mCase98;
	CButton m_mCase99;
	CButton m_mCase100;
	CButton m_mCase101;
	CButton m_mCase102;
	CButton m_mCase103;
	CButton m_mCase104;
	CButton m_mCase105;
	CButton m_mCase106;
	CButton m_mCase107;
	CButton m_mCase108;

	CRichEditCtrl m_mTestResult;
	CEdit m_mTestCnt;

	CButton m_mPoliceCase1;
	CButton m_mPoliceCase2;
	CButton m_mPoliceCase3;
	CButton m_mPoliceCase4;
	CButton m_mPoliceCase5;
	CButton m_mPoliceCase6;
	afx_msg void OnBnClickedButtonPolSelectAll();
	CButton m_mActivateCos;

public:
	HDEV hDevice;
	PDRIVE_METH m_pMeth;

	afx_msg void OnBnClickedButtonSelect();
	afx_msg void OnBnClickedButtonDownload();
	CEdit m_mFilePath;
	CEdit m_mSetAddr;
	afx_msg void OnBnClickedButtonSetAddr();
	afx_msg void OnBnClickedButtonVerifySha1();
	afx_msg void OnBnClickedButtonReadFlash();
	afx_msg void OnBnClickedButtonSelectPath();
	CEdit m_mSavePath;
	CEdit m_mPrifex;
	afx_msg void OnBnClickedButtonEnc();
	afx_msg void OnBnClickedButtonDec();
	CEdit m_mInputData;
	CEdit m_mPlainText;
	CEdit m_mIV;
	CEdit m_mAAD;
	CEdit m_mTAG;
	CEdit m_mCliper;
	afx_msg void OnBnClickedButtonClean();
};
