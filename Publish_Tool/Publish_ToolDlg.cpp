
// Publish_ToolDlg.cpp : ʵ���ļ�
//

#include <iostream>
#include <iomanip>
#include <fstream>

#include "stdafx.h"
#include "Publish_Tool.h"
#include "Publish_ToolDlg.h"
#include "afxdialogex.h"

#include "py_des.h"
#include "sm4_Hui.h"
#include "config.h"
#include "polarssl/rsa.h"
#include "polarssl/sm2.h"

#include "polarssl/sha1.h"

#pragma comment(lib,"CCWinDriver.lib")



#ifdef _DEBUG
#define new DEBUG_NEW
#endif



#define COLOR_RED		0xFF0000
#define COLOR_GREEN		0x00FF00
#define COLOR_BLUE		0x0000FF




struct threadInfo
{
	CPublish_ToolDlg *pDlg;
	CRichEditCtrl *pResult;
	CEdit *pCmd;
}ThreadInfo;


CString g_strExtName, g_strFilePath;
UINT g_fileLen = 0;
BYTE g_sha1Buf[20] = { 0 };


BYTE	GP_KEY_ENC[16] = {0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F};
BYTE	GP_KEY_MAC[16] = {0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F};
BYTE	GP_KEY_DEK[16] = {0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F};


//��¼��ǰ״̬��֧�ֵ�ָ��   by Huihh 2018.05.18
CString g_sSupportCmdList = NULL;

//��¼ͨ�ŷ�������
CString sValue;

//��¼���Խ��
ULONG g_ulTestRightCnt;
ULONG g_ulTestErrCnt;
CString g_sTestErrList;

ULONG g_ulPolTestRightCnt;
ULONG g_ulPolTestErrCnt;
CString g_sPolTestErrList;

//COSԭʼ���ݼ�¼
CString sw;
BYTE g_aCurDevAuthKey[16] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
BYTE g_aNewDevAuthKey[16] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
CString sVerPinHash = "0807060504030201080706050403020108070605040302010807060504030201";
CString sVerSoPinHash = "0001020304050607000102030405060700010203040506070001020304050607";
CString g_sHashValue;
CString g_sSignValue;

//���ڴ�ӡ����
BOOL g_bLogON = TRUE;


// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// �Ի�������
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CPublish_ToolDlg �Ի���




CPublish_ToolDlg::CPublish_ToolDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CPublish_ToolDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CPublish_ToolDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_COMBO_PORT, m_mPort);
	DDX_Control(pDX, IDC_RICHEDIT_RESULT, m_mResult);
	DDX_Control(pDX, IDC_CHECK_CREATE_FILE, m_mCreateFile);
	DDX_Control(pDX, IDC_CHECK_DELET_FILE, m_mDeleteFile);
	DDX_Control(pDX, IDC_CHECK_SELECT_FILE, m_mSelectFile);
	DDX_Control(pDX, IDC_CHECK_READ_FILE, m_mReadFile);
	DDX_Control(pDX, IDC_CHECK_WRITE_FILE, m_mWriteFile);
	DDX_Control(pDX, IDC_CHECK_GET_FILE_LIST, m_mGetFileList);
	DDX_Control(pDX, IDC_CHECK_GET_DEV_INFO, m_mGetDevInfo);
	DDX_Control(pDX, IDC_CHECK_SET_DEV_INFO, m_mSetDevInfo);
	DDX_Control(pDX, IDC_CHECK_GET_RAND, m_mGetRand);
	DDX_Control(pDX, IDC_CHECK_DEVICE_AUTH, m_mDeviceAuth);
	DDX_Control(pDX, IDC_CHECK_MODIFY_PIN, m_mModifyPin);
	DDX_Control(pDX, IDC_CHECK_GET_SESSION_KEY, m_mGetSessionKey);
	DDX_Control(pDX, IDC_CHECK_VERIFY_PIN, m_mVerifyPin);
	DDX_Control(pDX, IDC_CHECK_UNBLOCK_RESET_PIN, m_mUnBlockResetPin);
	DDX_Control(pDX, IDC_CHECK_IMPORT_PUBKEY, m_mImportPubKey);
	DDX_Control(pDX, IDC_CHECK_IMPORT_KEY, m_mImportKey);
	DDX_Control(pDX, IDC_CHECK_DELET_KEY, m_mDeletKey);
	DDX_Control(pDX, IDC_CHECK_SESSION_KEY_ALG, m_mSessionKeyAlg);
	DDX_Control(pDX, IDC_CHECK_SET_MODE, m_mSetMode);
	DDX_Control(pDX, IDC_CHECK_SYM_MAC, m_mSymMac);
	DDX_Control(pDX, IDC_CHECK_SYM_ENCRYPT, m_mSymEncrypt);
	DDX_Control(pDX, IDC_CHECK_SYM_DECRYPT, m_mSymDecrypt);
	DDX_Control(pDX, IDC_EDIT_SINGLE_CMD, m_mSingleCmd);
	DDX_Control(pDX, IDC_EDIT_CURRENT_STATE, m_mCurrentState);
	DDX_Control(pDX, IDC_COMBO_SET_STATE, m_mSetState);
	DDX_Control(pDX, IDC_CHECK_MODIFY_DEV_AUTH, m_mModDevAutKey);
	DDX_Control(pDX, IDC_CHECK_GET_APP_LIST, m_mGetAppList);
	DDX_Control(pDX, IDC_CHECK_GET_SM2_KEY, m_mGetSM2Key);
	DDX_Control(pDX, IDC_CHECK_GET_RSA_KEY, m_mGetRSAKey);
	DDX_Control(pDX, IDC_CHECK_GENARATE_RSA_KEY, m_mGenRSAKey);
	DDX_Control(pDX, IDC_CHECK_GENARATE_SM2_KEY, m_mGenSM2Key);
	DDX_Control(pDX, IDC_CHECK_SM3_HASH, m_mSM3Hash);
	DDX_Control(pDX, IDC_CHECK_SM2_SIGN, m_mSM2Sign);
	DDX_Control(pDX, IDC_CHECK_SM2_VERTFY, m_mSM2Vertfy);
	DDX_Control(pDX, IDC_CHECK_CREATE_FILE_DF1, m_mCreateDF1);
	DDX_Control(pDX, IDC_CHECK_CREATE_FILE_EF1, m_mCreateEF1);
	DDX_Control(pDX, IDC_CHECK_SELECT_FILE_DF1, m_mSelectDF1);
	DDX_Control(pDX, IDC_CHECK_SELECT_FILE_EF1, m_mSelectEF1);
	DDX_Control(pDX, IDC_CHECK_SELECT_FILE_MF, m_mSelectMF);
	DDX_Control(pDX, IDC_CHECK_CREATE_FILE_MF, m_mCreateMF);
	DDX_Control(pDX, IDC_TEST_CASE_1, m_mCase1);
	DDX_Control(pDX, IDC_TEST_CASE_2, m_mCase2);
	DDX_Control(pDX, IDC_TEST_CASE_3, m_mCase3);
	DDX_Control(pDX, IDC_TEST_CASE_4, m_mCase4);
	DDX_Control(pDX, IDC_TEST_CASE_5, m_mCase5);
	DDX_Control(pDX, IDC_TEST_CASE_6, m_mCase6);
	DDX_Control(pDX, IDC_TEST_CASE_7, m_mCase7);
	DDX_Control(pDX, IDC_TEST_CASE_8, m_mCase8);
	DDX_Control(pDX, IDC_TEST_CASE_9, m_mCase9);
	DDX_Control(pDX, IDC_TEST_CASE_10, m_mCase10);
	DDX_Control(pDX, IDC_TEST_CASE_11, m_mCase11);
	DDX_Control(pDX, IDC_TEST_CASE_12, m_mCase12);
	DDX_Control(pDX, IDC_TEST_CASE_13, m_mCase13);
	DDX_Control(pDX, IDC_TEST_CASE_14, m_mCase14);
	DDX_Control(pDX, IDC_TEST_CASE_15, m_mCase15);
	DDX_Control(pDX, IDC_TEST_CASE_16, m_mCase16);
	DDX_Control(pDX, IDC_TEST_CASE_17, m_mCase17);
	DDX_Control(pDX, IDC_TEST_CASE_18, m_mCase18);
	DDX_Control(pDX, IDC_TEST_CASE_19, m_mCase19);
	DDX_Control(pDX, IDC_TEST_CASE_20, m_mCase20);
	DDX_Control(pDX, IDC_TEST_CASE_21, m_mCase21);
	DDX_Control(pDX, IDC_TEST_CASE_22, m_mCase22);
	DDX_Control(pDX, IDC_TEST_CASE_23, m_mCase23);
	DDX_Control(pDX, IDC_TEST_CASE_24, m_mCase24);
	DDX_Control(pDX, IDC_TEST_CASE_25, m_mCase25);
	DDX_Control(pDX, IDC_TEST_CASE_26, m_mCase26);
	DDX_Control(pDX, IDC_TEST_CASE_27, m_mCase27);
	DDX_Control(pDX, IDC_TEST_CASE_28, m_mCase28);
	DDX_Control(pDX, IDC_TEST_CASE_29, m_mCase29);
	DDX_Control(pDX, IDC_TEST_CASE_30, m_mCase30);
	DDX_Control(pDX, IDC_TEST_CASE_31, m_mCase31);
	DDX_Control(pDX, IDC_TEST_CASE_32, m_mCase32);
	DDX_Control(pDX, IDC_TEST_CASE_33, m_mCase33);
	DDX_Control(pDX, IDC_TEST_CASE_34, m_mCase34);
	DDX_Control(pDX, IDC_TEST_CASE_35, m_mCase35);
	DDX_Control(pDX, IDC_TEST_CASE_36, m_mCase36);
	DDX_Control(pDX, IDC_TEST_CASE_37, m_mCase37);
	DDX_Control(pDX, IDC_TEST_CASE_38, m_mCase38);
	DDX_Control(pDX, IDC_TEST_CASE_39, m_mCase39);
	DDX_Control(pDX, IDC_TEST_CASE_40, m_mCase40);
	DDX_Control(pDX, IDC_TEST_CASE_41, m_mCase41);
	DDX_Control(pDX, IDC_TEST_CASE_42, m_mCase42);
	DDX_Control(pDX, IDC_TEST_CASE_43, m_mCase43);
	DDX_Control(pDX, IDC_TEST_CASE_44, m_mCase44);
	DDX_Control(pDX, IDC_TEST_CASE_45, m_mCase45);
	DDX_Control(pDX, IDC_TEST_CASE_46, m_mCase46);
	DDX_Control(pDX, IDC_TEST_CASE_47, m_mCase47);
	DDX_Control(pDX, IDC_TEST_CASE_48, m_mCase48);
	DDX_Control(pDX, IDC_TEST_CASE_49, m_mCase49);
	DDX_Control(pDX, IDC_TEST_CASE_50, m_mCase50);
	DDX_Control(pDX, IDC_TEST_CASE_51, m_mCase51);
	DDX_Control(pDX, IDC_TEST_CASE_52, m_mCase52);
	DDX_Control(pDX, IDC_TEST_CASE_53, m_mCase53);
	DDX_Control(pDX, IDC_TEST_CASE_54, m_mCase54);
	DDX_Control(pDX, IDC_TEST_CASE_55, m_mCase55);
	DDX_Control(pDX, IDC_TEST_CASE_56, m_mCase56);
	DDX_Control(pDX, IDC_TEST_CASE_57, m_mCase57);
	DDX_Control(pDX, IDC_TEST_CASE_58, m_mCase58);
	DDX_Control(pDX, IDC_TEST_CASE_59, m_mCase59);
	DDX_Control(pDX, IDC_TEST_CASE_60, m_mCase60);
	DDX_Control(pDX, IDC_TEST_CASE_61, m_mCase61);
	DDX_Control(pDX, IDC_TEST_CASE_62, m_mCase62);
	DDX_Control(pDX, IDC_TEST_CASE_63, m_mCase63);
	DDX_Control(pDX, IDC_TEST_CASE_64, m_mCase64);
	DDX_Control(pDX, IDC_TEST_CASE_65, m_mCase65);
	DDX_Control(pDX, IDC_TEST_CASE_66, m_mCase66);
	DDX_Control(pDX, IDC_TEST_CASE_67, m_mCase67);
	DDX_Control(pDX, IDC_TEST_CASE_68, m_mCase68);
	DDX_Control(pDX, IDC_TEST_CASE_69, m_mCase69);
	DDX_Control(pDX, IDC_TEST_CASE_70, m_mCase70);
	DDX_Control(pDX, IDC_TEST_CASE_71, m_mCase71);
	DDX_Control(pDX, IDC_TEST_CASE_72, m_mCase72);
	DDX_Control(pDX, IDC_TEST_CASE_73, m_mCase73);
	DDX_Control(pDX, IDC_TEST_CASE_74, m_mCase74);
	DDX_Control(pDX, IDC_TEST_CASE_75, m_mCase75);
	DDX_Control(pDX, IDC_TEST_CASE_76, m_mCase76);
	DDX_Control(pDX, IDC_TEST_CASE_77, m_mCase77);
	DDX_Control(pDX, IDC_TEST_CASE_78, m_mCase78);
	DDX_Control(pDX, IDC_TEST_CASE_79, m_mCase79);
	DDX_Control(pDX, IDC_TEST_CASE_80, m_mCase80);
	DDX_Control(pDX, IDC_TEST_CASE_81, m_mCase81);
	DDX_Control(pDX, IDC_TEST_CASE_82, m_mCase82);
	DDX_Control(pDX, IDC_TEST_CASE_83, m_mCase83);
	DDX_Control(pDX, IDC_TEST_CASE_84, m_mCase84);
	DDX_Control(pDX, IDC_TEST_CASE_85, m_mCase85);
	DDX_Control(pDX, IDC_TEST_CASE_86, m_mCase86);
	DDX_Control(pDX, IDC_TEST_CASE_87, m_mCase87);
	DDX_Control(pDX, IDC_TEST_CASE_88, m_mCase88);
	DDX_Control(pDX, IDC_TEST_CASE_89, m_mCase89);
	DDX_Control(pDX, IDC_TEST_CASE_90, m_mCase90);
	DDX_Control(pDX, IDC_TEST_CASE_91, m_mCase91);
	DDX_Control(pDX, IDC_TEST_CASE_92, m_mCase92);
	DDX_Control(pDX, IDC_TEST_CASE_93, m_mCase93);
	DDX_Control(pDX, IDC_TEST_CASE_94, m_mCase94);
	DDX_Control(pDX, IDC_TEST_CASE_95, m_mCase95);
	DDX_Control(pDX, IDC_TEST_CASE_96, m_mCase96);
	DDX_Control(pDX, IDC_TEST_CASE_97, m_mCase97);
	DDX_Control(pDX, IDC_TEST_CASE_98, m_mCase98);
	DDX_Control(pDX, IDC_TEST_CASE_99, m_mCase99);
	DDX_Control(pDX, IDC_TEST_CASE_100, m_mCase100);
	DDX_Control(pDX, IDC_TEST_CASE_101, m_mCase101);
	DDX_Control(pDX, IDC_TEST_CASE_102, m_mCase102);
	DDX_Control(pDX, IDC_TEST_CASE_103, m_mCase103);
	DDX_Control(pDX, IDC_TEST_CASE_104, m_mCase104);
	DDX_Control(pDX, IDC_TEST_CASE_105, m_mCase105);
	DDX_Control(pDX, IDC_TEST_CASE_106, m_mCase106);
	DDX_Control(pDX, IDC_TEST_CASE_107, m_mCase107);
	DDX_Control(pDX, IDC_TEST_CASE_108, m_mCase108);

	DDX_Control(pDX, IDC_COS_TEST_RESULT, m_mTestResult);
	DDX_Control(pDX, IDC_COS_TEST_CNT, m_mTestCnt);
	DDX_Control(pDX, IDC_POL_TEST_1, m_mPoliceCase1);
	DDX_Control(pDX, IDC_POL_TEST_2, m_mPoliceCase2);
	DDX_Control(pDX, IDC_POL_TEST_3, m_mPoliceCase3);
	DDX_Control(pDX, IDC_POL_TEST_4, m_mPoliceCase4);
	DDX_Control(pDX, IDC_POL_TEST_5, m_mPoliceCase5);
	DDX_Control(pDX, IDC_POL_TEST_6, m_mPoliceCase6);
	DDX_Control(pDX, IDC_CHECK_ACTIVATE_COS, m_mActivateCos);
	DDX_Control(pDX, IDC_EDIT_FILE_NAME, m_mFilePath);
	DDX_Control(pDX, IDC_EDIT_ADDR, m_mSetAddr);
	DDX_Control(pDX, IDC_EDIT_SAVE_PATH, m_mSavePath);
	DDX_Control(pDX, IDC_EDIT_PREFIX, m_mPrifex);
}

BEGIN_MESSAGE_MAP(CPublish_ToolDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON_REFRESH_READER, &CPublish_ToolDlg::OnClickedButtonRefreshReader)
	ON_BN_CLICKED(IDC_BUTTON_OPEN_CLOSE, &CPublish_ToolDlg::OnClickedButtonOpenClose)
	ON_BN_CLICKED(IDC_BUTTON_CLEAR, &CPublish_ToolDlg::OnBnClickedButtonClear)
	ON_BN_CLICKED(IDC_BUTTON_EXECUTE, &CPublish_ToolDlg::OnBnClickedButtonExecute)
	ON_BN_CLICKED(IDC_BUTTON_FS_SELECT_ALL, &CPublish_ToolDlg::OnBnClickedButtonFsSelectAll)
	ON_BN_CLICKED(IDC_BUTTON_BUSNISS_SELECT_ALL, &CPublish_ToolDlg::OnBnClickedButtonBusnissSelectAll)
	ON_BN_CLICKED(IDC_BUTTON_IKI_SELECT_ALL, &CPublish_ToolDlg::OnBnClickedButtonIkiselectAll)
	ON_BN_CLICKED(IDC_BUTTON_SEND_CMD, &CPublish_ToolDlg::OnBnClickedButtonSendCmd)
	ON_BN_CLICKED(IDC_BUTTON_GET_CURRENT_STATE, &CPublish_ToolDlg::OnBnClickedButtonGetCurrentState)
	ON_BN_CLICKED(IDC_BUTTON_SET_STATE, &CPublish_ToolDlg::OnBnClickedButtonSetState)
	ON_BN_CLICKED(IDC_BUTTON_POL_SELECT_ALL, &CPublish_ToolDlg::OnBnClickedButtonPolSelectAll)
	ON_BN_CLICKED(IDC_BUTTON_SELECT, &CPublish_ToolDlg::OnBnClickedButtonSelect)
	ON_BN_CLICKED(IDC_BUTTON_DOWNLOAD, &CPublish_ToolDlg::OnBnClickedButtonDownload)
	ON_BN_CLICKED(IDC_BUTTON_SET_ADDR, &CPublish_ToolDlg::OnBnClickedButtonSetAddr)
	ON_BN_CLICKED(IDC_BUTTON_VERIFY_SHA1, &CPublish_ToolDlg::OnBnClickedButtonVerifySha1)
	ON_BN_CLICKED(IDC_BUTTON_READ_FLASH, &CPublish_ToolDlg::OnBnClickedButtonReadFlash)
	ON_BN_CLICKED(IDC_BUTTON_SELECT_PATH, &CPublish_ToolDlg::OnBnClickedButtonSelectPath)
END_MESSAGE_MAP()


// CPublish_ToolDlg ��Ϣ�������

BOOL CPublish_ToolDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// ��������...���˵�����ӵ�ϵͳ�˵��С�


	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// ���ô˶Ի����ͼ�ꡣ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO: �ڴ���Ӷ���ĳ�ʼ������
	CC_GetDriveMeth(&m_pMeth, 0);

	SetDlgItemText(IDC_EDIT_ADDR, "0x00008000");
	SetDlgItemText(IDC_EDIT_SINGLE_CMD, "8082000040");
	SetDlgItemText(IDC_EDIT_PREFIX, "06");

	SetDlgItemText(IDC_EDIT_SAVE_PATH, "E:\\Work\\PYTHON\\SD\\log.txt");

	pWinThread = NULL;
	ThreadInfo.pDlg = this;
	ThreadInfo.pResult = &m_mResult;

	m_mSetState.AddString(_T("70"));
	m_mSetState.AddString(_T("71"));
	m_mSetState.AddString(_T("72"));

	m_mSetState.SetCurSel(0);


	GetDlgItem(IDC_BUTTON_FS_SELECT_ALL)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_BUSNISS_SELECT_ALL)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_IKI_SELECT_ALL)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_POL_SELECT_ALL)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_EXECUTE)->EnableWindow(FALSE);

	GetDlgItem(IDC_BUTTON_SEND_CMD)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_GET_CURRENT_STATE)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_SET_STATE)->EnableWindow(FALSE);

	GetDlgItem(IDC_BUTTON_SET_ADDR)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_DOWNLOAD)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_VERIFY_SHA1)->EnableWindow(FALSE);

	GetDlgItem(IDC_BUTTON_READ_FLASH)->EnableWindow(FALSE);


	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
}

void CPublish_ToolDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CPublish_ToolDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
HCURSOR CPublish_ToolDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}




BOOL CPublish_ToolDlg::TerminateThreadExecute(CWinThread *pWinThread)
{
	if (pWinThread != NULL)
	{
		DWORD exit;

		GetExitCodeThread(pWinThread->m_hThread, &exit);
		TerminateThread(pWinThread->m_hThread, exit);
		pWinThread->m_hThread = NULL;
	}

	return TRUE;
}







void CPublish_ToolDlg::DisplayReaders()
{
	m_mPort.ResetContent();    //Can`t Delete this, Otherwise Display ReaderList also Add one by one   by Huihh 2016.9.7
	m_mPort.Clear();

	for (int i=0; i<ArrayReaderList.GetSize(); i++)
	{
		m_mPort.AddString(ArrayReaderList.GetAt(i));
	}

	m_mPort.SetCurSel(1);     //Default select contact reader    by Huihh 2018.05.15
}


//Display Message in Result Edit   
void CPublish_ToolDlg::ShowMessageString(CString Message)
{
	if (g_bLogON)
	{
		int len = m_mResult.GetWindowTextLengthA();

		if ((len + Message.GetLength()) > (m_mResult.GetLimitText()))
		{
			m_mResult.SetWindowTextA(_T("Clear Screen ...\r\n"));
		}

		Message += "\r\n";

		m_mResult.SetSel(-1, -1);
		m_mResult.ReplaceSel(Message);
		m_mResult.PostMessageA(WM_VSCROLL, SB_BOTTOM, 0);
	}
	
}

//Display Message Higher Color in Result Edit
void CPublish_ToolDlg::ShowMessageStringAlert(CString Message, int color)
{
	CHARFORMAT	cf;

	int r, g, b;
	r = ((color >> 16) & 0xFF);
	g = ((color >>  8) & 0xFF);
	b = ((color >>  0) & 0xFF);

	memset(&cf, 0, sizeof(cf));
	m_mResult.GetDefaultCharFormat(cf);

	cf.dwMask = CFM_COLOR;
	cf.dwEffects &= ~CFE_AUTOCOLOR;

	cf.crTextColor = RGB(r, g, b);

	m_mResult.SetSel(-1, -1);
	m_mResult.SetSelectionCharFormat(cf);

	ShowMessageString(Message);
}


INT CPublish_ToolDlg::ResetCard(INT DisplayFlag)
{

	CString sDisp, sTemp;

	if (hCard != NULL)
	{
		dwRetCode = SCardEndTransaction(hCard, SCARD_LEAVE_CARD);
		dwRetCode = SCardDisconnect(hCard, SCARD_RESET_CARD);
		hCard = NULL;
	}

	PCSCReaderName = ArrayReaderList.GetAt(m_mPort.GetCurSel());

	dwRetCode = SCardConnect(hContext, PCSCReaderName, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0|SCARD_PROTOCOL_T1, &hCard, &AProtocol);

	if (dwRetCode != SCARD_S_SUCCESS)
	{
		AfxMessageBox(_T("Reset Failed , Please Try Again Later "));
		return 1;
	}

	memset(ATRBuf, 0, sizeof(ATRBuf));
	
	ATRBufLen = 256;   //Must Init This Value, Otherwise  lead to invoking SCardListReaders() Function Return Error   by Huihh 2016.9.7

	dwRetCode = SCardStatusA(hCard, ReaderBuf, &ReaderBufLen, &dwState, &dwProtocol, (LPBYTE)ATRBuf, &ATRBufLen);

	if (dwRetCode != SCARD_S_SUCCESS)
	{
		AfxMessageBox(_T("Gain Scard Status Failed, Please Try Again Later "));
		return 1;
	}

	for (int i=0; i<ATRBufLen; i++)
	{
		sTemp.Format("%02x", ATRBuf[i]);
		sDisp += sTemp;
	}
	sDisp.MakeUpper();	//Display ATR make Upper   by Huihh 2016.9.8

	if (DisplayFlag == 0)
	{
		return 0;
	}
	else if (DisplayFlag == 1)
	{
		ShowMessageString("ATR: " + sDisp);
	}
	else
	{
		ShowMessageStringAlert("ResetCard Function Param Error !\n", COLOR_RED);
	}


	return 0;
}



int CPublish_ToolDlg::TransmitData_PCSC(BYTE SendBuf[], int SendLen, BYTE RecvBuf[], unsigned long *RecvLen)
{
	BYTE hexCmd[256] = {0};
	int  hexCmdLen = 0;



	unsigned long BackupLen = *RecvLen;

	SCARD_IO_REQUEST	pIOSendRequest;



	memset(&pIOSendRequest, 0, sizeof(pIOSendRequest));

	pIOSendRequest.dwProtocol = AProtocol;
	pIOSendRequest.cbPciLength = sizeof(SCARD_IO_REQUEST);

	dwRetCode = SCardTransmit(hCard, &pIOSendRequest, SendBuf, SendLen, NULL, RecvBuf, RecvLen);

	if ((*RecvLen == 2) && (RecvBuf[0] == 0x61))
	{
		memset(&pIOSendRequest, 0, sizeof(pIOSendRequest));
		pIOSendRequest.dwProtocol = AProtocol;
		pIOSendRequest.cbPciLength = sizeof(SCARD_IO_REQUEST);

		memcpy(hexCmd, "\x00\xC0\x00\x00", 4);
		hexCmd[4]= RecvBuf[1];
		hexCmdLen = 5;

		*RecvLen = BackupLen;
		dwRetCode = SCardTransmit(hCard, &pIOSendRequest, hexCmd, hexCmdLen, NULL, RecvBuf, RecvLen);
	}
	else if((*RecvLen == 2) && (RecvBuf[0] == 0x6C))
	{
		memset(&pIOSendRequest, 0, sizeof(pIOSendRequest));
		pIOSendRequest.dwProtocol = AProtocol;
		pIOSendRequest.cbPciLength = sizeof(SCARD_IO_REQUEST);

		memcpy(hexCmd, SendBuf, 4);
		hexCmd[4]= ReaderBuf[1];
		hexCmdLen = 5;

		*RecvLen = BackupLen;
		dwRetCode = SCardTransmit(hCard, &pIOSendRequest, hexCmd, hexCmdLen, NULL, RecvBuf, RecvLen);

	}

	return dwRetCode;
}











BOOL CPublish_ToolDlg::GPProcess(void)
{
	BYTE hostRandom[8] = {0};
	BYTE cardRandom[6] = {0};
	BYTE seqCounter[2] = {0};

	BYTE SendBuf[256] = {0};
	unsigned long SendLen = 0;

	BYTE RecvBuf[256] = {0};
	unsigned long RecvLen = 256;


	BYTE waitEncBuf[24] = {0};

	CString sDisp, sTemp;
	int Ret;


	for (int i=0; i<8; i++)
	{
		hostRandom[i] = rand() % ((BYTE)0xFF);
	}

	memcpy(SendBuf, "\x80\x50\x00\x00\x08", 5);
	memcpy(SendBuf+5, hostRandom, 8);
	SendLen = 5+8;

	sDisp = "-->: ";
	for (int i=0; i<SendLen; i++)
	{
		sTemp.Format("%02x", SendBuf[i]);
		sDisp += sTemp;
	}
	sDisp.MakeUpper();
	ShowMessageString(sDisp);

	Ret = TransmitData_PCSC(SendBuf, SendLen, RecvBuf, &RecvLen);

	if (Ret != SCARD_S_SUCCESS)
	{
		AfxMessageBox(_T("Transmit Instruction Failed, Try Again"));
		return FALSE;
	}


	sDisp = "<--: ";
	for (int i=0; i<RecvLen; i++)
	{
		sTemp.Format("%02x", RecvBuf[i]);
		sDisp += sTemp;
	}
	sDisp.MakeUpper();
	sDisp.Insert(sDisp.GetLength()-4, "  ");

	if ((RecvBuf[RecvLen-2] == 0x90) && (RecvBuf[RecvLen-1] == 0x00))
	{
		ShowMessageString(sDisp);
	}
	else
	{
		ShowMessageStringAlert(sDisp, COLOR_RED);
	}


	//��Ƭ����������֯   Key diversification(10Bytes) | key information(2Bytes) | sequence Counter(2Bytes) | card challenge(6bytes) | card cryptogram(8BYtes)


	//����GP�Ự��Կ   by Huihh 2017.04.21
	// Key Enc('0182'|| Sequence Counter || '000000000000000000000000')
	memset(waitEncBuf, 0, sizeof(waitEncBuf));
	memcpy(waitEncBuf, "\x01\x82", 2);                 
	memcpy(waitEncBuf+2, RecvBuf+12, 2);

	Lib_Des16CBC(waitEncBuf, 16, SessionKey_ENC, GP_KEY_ENC, MODE_ENCRYPT);   //����ENCֵ    SessionKey_ENC    by Huihh  2017.03.21
	//	memcpy(ENC_Session_Key, SessionKey_ENC, sizeof(SessionKey_ENC));


	// Key Mac('0101'|| Sequence Counter || '000000000000000000000000')
	memset(waitEncBuf, 0, sizeof(waitEncBuf));
	memcpy(waitEncBuf, "\x01\x01", 2);                 
	memcpy(waitEncBuf+2, RecvBuf+12, 2);

	Lib_Des16CBC(waitEncBuf, 16, SessionKey_MAC, GP_KEY_MAC, MODE_ENCRYPT);   //����MACֵ    SessionKey_MAC    by Huihh  2017.04.21
	//	memcpy(MAC_Session_Key, SessionKey_MAC, sizeof(SessionKey_MAC));



	// Key Dek('0181'|| Sequence Counter || '000000000000000000000000')
	memset(waitEncBuf, 0, sizeof(waitEncBuf));
	memcpy(waitEncBuf, "\x01\x81", 2);                 
	memcpy(waitEncBuf+2, RecvBuf+12, 2);

	Lib_Des16CBC(waitEncBuf, 16, SessionKey_DEK, GP_KEY_DEK, MODE_ENCRYPT);   //����DEKֵ    SessionKey_DEK    by Huihh  2017.04.21
	//	memcpy(DEK_Session_Key, SessionKey_DEK, sizeof(SessionKey_DEK));





	memcpy(cardRandom, RecvBuf+14, 6);    //cardRandom ��� card challenge(6bytes)
	memcpy(seqCounter, RecvBuf+12, 2);    //seqCounter ��� sequence Counter(2Bytes)


	//������֯   hostRandom(8) + seqCounter(2)
	memset(waitEncBuf, 0, sizeof(waitEncBuf));
	memcpy(waitEncBuf, hostRandom, 8);
	memcpy(waitEncBuf+8, seqCounter, 2);
	memcpy(waitEncBuf+10, cardRandom, 6);
	memcpy(waitEncBuf+16, "\x80\x00\x00\x00\x00\x00\x00\x00", 8);

	Lib_Des16CBC(waitEncBuf, 24, waitEncBuf, SessionKey_ENC, MODE_ENCRYPT);


	if (memcmp(waitEncBuf+16, RecvBuf+20, 8) != 0)
	{
		ShowMessageStringAlert(_T("Cryptogram is Not  Equal between Terminal and Card"), COLOR_RED);
		return FALSE;
	}


	//seqCounter(2�ֽ�) + cardRandom(6�ֽ�) + hostRandom(8�ֽ�)
	memset(waitEncBuf, 0, sizeof(waitEncBuf));
	memcpy(waitEncBuf, seqCounter, 2);
	memcpy(waitEncBuf+2, cardRandom, 6);
	memcpy(waitEncBuf+8, hostRandom, 8);
	memcpy(waitEncBuf+16, "\x80\x00\x00\x00\x00\x00\x00\x00", 8);

	Lib_Des16CBC(waitEncBuf, 24, waitEncBuf, SessionKey_ENC, MODE_ENCRYPT);

	memcpy(hostRandom, waitEncBuf+16, 8);


	memset(waitEncBuf, 0, sizeof(waitEncBuf));
	memcpy(waitEncBuf, "\x84\x82\x00\x00\x10", 5);
	memcpy(waitEncBuf+5, hostRandom, 8);

	Lib_Des3_16Mac(SessionKey_MAC, waitEncBuf, 13);


	memset(SendBuf, 0, sizeof(SendBuf));
	memcpy(SendBuf, "\x84\x82\x00\x00\x10", 5);
	memcpy(SendBuf+5, hostRandom, 8);
	memcpy(SendBuf+13, waitEncBuf, 8);     // MAC is in GP  8-Octets   by Huihh 2016.9.8

	SendLen = 5+8+8;


	sDisp = "-->: ";
	for (int i=0; i<SendLen; i++)
	{
		sTemp.Format("%02x", SendBuf[i]);
		sDisp += sTemp;
	}
	sDisp.MakeUpper();
	ShowMessageString(sDisp);

	Ret = TransmitData_PCSC(SendBuf, SendLen, RecvBuf, &RecvLen);

	if (Ret != SCARD_S_SUCCESS)
	{
		AfxMessageBox(_T("Transmit Instruction Failed, Try Again"));
		return FALSE;
	}


	sDisp = "<--: ";

	for (int i=0; i<RecvLen; i++)
	{
		sTemp.Format("%02x", RecvBuf[i]);
		sDisp += sTemp;
	}
	sDisp.MakeUpper();
	sDisp.Insert(sDisp.GetLength()-4, "  ");

	if ((RecvBuf[RecvLen-2] == 0x90) && (RecvBuf[RecvLen-1] == 0x00))
	{
		ShowMessageString(sDisp);
	}
	else
	{
		ShowMessageStringAlert(sDisp, COLOR_RED);
	}

	return TRUE;
}


//Ascii convert to Hex 
BOOL CPublish_ToolDlg::AsciiToHex(BYTE pAsciiArray[], BYTE pHexArray[], int Len)
{
	BYTE tempBuf[2]={0};

	if (Len %2 != 0)
	{
		AfxMessageBox(_T("Ascii Convert Hex Failed, Please input Convert Length in even numbers, Try Again Later"));
		return FALSE;
	}

	int HexLen = Len / 2;   // 2 Character Convert 1 Hex  by Huihh 2016.9.8

	for (int i=0; i<HexLen; i++)
	{
		tempBuf[0] = *pAsciiArray++;
		tempBuf[1] = *pAsciiArray++;

		for (int j=0; j<2; j++)
		{
			if (tempBuf[j] <= 'F' && tempBuf[j] >= 'A')
			{
				tempBuf[j] = tempBuf[j] - 'A' + 10;
			}
			else if (tempBuf[j] <= 'f' && tempBuf[j] >= 'a')
			{
				tempBuf[j] = tempBuf[j] - 'a' + 10;
			}
			else if (tempBuf[j] >= '0' && tempBuf[j] <= '9')
			{
				tempBuf[j] = tempBuf[j] - '0';
			}
			else
			{
				AfxMessageBox(_T("pAsciiArray Contain illegality Character, Please Try Again after Check "));
				return FALSE;
			}
		}

		pHexArray[i] = tempBuf[0] << 4;    
		pHexArray[i] |= tempBuf[1];
	}

	return TRUE;

}
















//SendCommand Instruction to Smart card  pass to PCSC Reader
CString CPublish_ToolDlg::SendCommandGetValueOrSW(CString sCmd, int Flag)
{
	int Rtn;
	CString sSW;

	BYTE ascCmd[8*1024] = {0};    //����256->1024   ����ΪдDGI = 0201ʱ�ᱨ��    by Huihh 2016.11.11  
	WORD ascCmdLen = 0;

	BYTE hexCmd[8*1024] = {0};
	WORD hexCmdLen = 0;

	BYTE RecvBuf[8*1024] = {0};
	unsigned long RecvBufLen = 4*1024; 

	CString sDisp, sTemp;

	sValue.Empty();
	sCmd.Remove(' ');  // Remove space in cmd

	if (sCmd.GetLength() == 0)
	{
		ShowMessageStringAlert(_T("Instruction is NULL, Please Try Again after insert your Instruction"), COLOR_RED);
		return NULL;
	}

	if (sCmd.GetLength() % 2 != 0)
	{
		ShowMessageStringAlert(_T("Your Instruction is illegality(even Character), Try Again after Check"), COLOR_RED);
		return NULL;
	}

	if (sCmd.GetLength() / 2 < 5)
	{
		ShowMessageStringAlert(_T("Your Instruction is illegality(Must be Equal Or Greater than Five Character), Try Again after Check"), COLOR_RED);
		return NULL;
	}


	CString sPrifix;
	GetDlgItemText(IDC_EDIT_PREFIX, sPrifix);

	if (sPrifix.GetLength() != 2) {
		ShowMessageStringAlert(_T("sPrifix is 1 Octet, Range is (00, 01, 02, 03, 04, 05, 06, 07, FF), Please Try Again"), COLOR_RED);
		return NULL;
	}

	sCmd = sPrifix + sCmd;

	strcpy((char *)ascCmd, sCmd);
	ascCmdLen = strlen((char *)ascCmd);

	AsciiToHex(ascCmd, hexCmd, ascCmdLen);
	hexCmdLen = ascCmdLen / 2;

	sDisp = "-->: ";
	for (int i=0; i<(hexCmdLen-1); i++)
	{
		sTemp.Format("%02x", hexCmd[i+1]);
		sDisp += sTemp;
	}
	sDisp.MakeUpper();

	if (Flag != 3)  //����ʾ  by Huihh 2017.08.30
	{
		ShowMessageString(sDisp);
	}


ww:
	if (Rtn = m_pMeth->WriteDeviceData(hDevice, hexCmd, hexCmdLen))
	{
		AfxMessageBox(_T("д���ݵ��豸ʧ�ܣ�"));
		goto err;
	}
	do
	{
		if (Rtn = m_pMeth->ReadDeviceData(hDevice, RecvBuf, &RecvBufLen))
		{
			if (Rtn == DR_RD_BUSY)
			{
				//Sleep(10);
				continue;
			}
			else if (Rtn == DR_RD_DATA)
			{
				goto ww;
			}
			else
			{
				AfxMessageBox(_T("���豸������ʧ�ܣ�"));
				goto err;
			}
		}
		else {
			break;
		}

	} while (1);


	sDisp = "<--: ";
	for (int i=0; i<RecvBufLen; i++)
	{
		sTemp.Format("%02x", RecvBuf[i]);
		sDisp += sTemp;

		if (i <(RecvBufLen-2))
		{
			sValue += sTemp;
		}

		if (i >= (RecvBufLen-2))
		{
			sSW += sTemp;
		}
	}
	sDisp.Insert(sDisp.GetLength()-4, "  ");
	sDisp.MakeUpper();

	sValue.MakeUpper();
	sSW.MakeUpper();


	if (sSW == "9000") {
		ShowMessageString(sDisp);
	}
	else {
		ShowMessageStringAlert(sDisp, COLOR_RED);
	}

	if ( (Flag == 0) || (Flag == 3) ) //return value         3���ڲ���ʾָ�� by Huihh 2017.08.30
	{
		return sValue;
	}
	else          //return SW
	{
		return sSW;
	}



err:
	m_pMeth->CloseDevice(hDevice);
	return NULL;

}



BOOL CPublish_ToolDlg::ExAuthen(CString sKey)
{
	BYTE SendBuf[256] = { 0 };
	unsigned long SendLen = 0;

	BYTE RecvBuf[256] = { 0 };
	unsigned long RecvLen = 256;

	BYTE RandomBuf[16] = { 0 };
	BYTE EncDataBuf[16] = { 0 };

	CString sDisp, sTemp;

	int Ret;

	BYTE AuthKey[16] = { 0 };

	memcpy(SendBuf, "\x00\x84\x00\x00\x08", 5);
	SendLen = 5;

	sDisp = "-->: ";
	for (int i = 0; i<SendLen; i++)
	{
		sTemp.Format("%02x", SendBuf[i]);
		sDisp += sTemp;
	}
	sDisp.MakeUpper();

	ShowMessageString(sDisp);

	Ret = TransmitData_PCSC(SendBuf, SendLen, RecvBuf, &RecvLen);

	if (Ret != SCARD_S_SUCCESS)
	{
		AfxMessageBox(_T("Transmit Instruction Failed, Try Again"));
		return FALSE;
	}

	sDisp = "<--: ";
	for (int i = 0; i<RecvLen; i++)
	{
		sTemp.Format("%02x", RecvBuf[i]);
		sDisp += sTemp;
	}

	sDisp.MakeUpper();
	sDisp.Insert(sDisp.GetLength() - 4, "  ");

	if ((RecvBuf[RecvLen - 2] == 0x90) && (RecvBuf[RecvLen - 1] == 0x00))
	{
		ShowMessageString(sDisp);
	}
	else
	{
		ShowMessageStringAlert(sDisp, COLOR_RED);
	}

	memcpy(RandomBuf, RecvBuf, 8);    //RandomBuf just use 8-Octet, remain 8-Octet use for GM Algorithm    by Huihh 2016.9.9

	memset(RecvBuf, 0, sizeof(RecvBuf));
	strcpy((char *)RecvBuf, sKey);

	AsciiToHex(RecvBuf, AuthKey, strlen((char *)RecvBuf));

	Lib_Des16ECB(RandomBuf, EncDataBuf, AuthKey, MODE_ENCRYPT);

	memset(SendBuf, 0, sizeof(SendLen));

	memcpy(SendBuf, "\x00\x82\x00\x00\x08", 5);   //GL Alg = 08,  GM Alg = 0x10    by Huihh 2016.9.9
	memcpy(SendBuf + 5, EncDataBuf, 8);
	SendLen = 5 + 8;

	sDisp = "-->: ";
	for (int i = 0; i<SendLen; i++)
	{
		sTemp.Format("%02x", SendBuf[i]);
		sDisp += sTemp;
	}
	sDisp.MakeUpper();

	ShowMessageString(sDisp);

	Ret = TransmitData_PCSC(SendBuf, SendLen, RecvBuf, &RecvLen);
	if (Ret != SCARD_S_SUCCESS)
	{
		AfxMessageBox(_T("Transmit Instruction Failed, Try Again"));
		return FALSE;
	}

	sDisp = "<--: ";
	for (int i = 0; i<RecvLen; i++)
	{
		sTemp.Format("%02x", RecvBuf[i]);
		sDisp += sTemp;
	}
	sDisp.MakeUpper();
	sDisp.Insert(sDisp.GetLength() - 4, "  ");

	if ((RecvBuf[RecvLen - 2] == 0x90) && (RecvBuf[RecvLen - 1] == 0x00))
	{
		ShowMessageString(sDisp);
	}
	else
	{
		ShowMessageStringAlert(sDisp, COLOR_RED);
	}


	return TRUE;
}





void CPublish_ToolDlg::CstringToByte(CString sInput, BYTE bOutput[])
{
	BYTE srcBuf[1024] = { 0 };	// The Bigger the better     by Huihh 2016.9.12
	BYTE desBuf[1024] = { 0 };
	int srcLen = 0;


	strcpy((char *)srcBuf, sInput);
	srcLen = strlen(sInput);


	AsciiToHex(srcBuf, desBuf, srcLen);   //�������볤��Ϊ�ַ��ĸ���   by Huihh 2016.11.11

	for (int i = 0; i<(srcLen / 2); i++)
	{
		bOutput[i] = desBuf[i];
	}

}





void CPublish_ToolDlg::OnBnClickedButtonClear()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	m_mResult.SetWindowTextA(_T(""));
	m_mTestResult.SetWindowTextA(_T(""));
}






void CPublish_ToolDlg::OnClickedButtonRefreshReader()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������

	TCHAR buf[128] = { 0 };
	CString str;
	DWORD len = GetLogicalDriveStrings(sizeof(buf) / sizeof(TCHAR), buf);
	UINT uType = 0, exist = 0;
	TCHAR* p = NULL;


	GetDlgItem(IDC_BUTTON_FS_SELECT_ALL)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_BUSNISS_SELECT_ALL)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_IKI_SELECT_ALL)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_POL_SELECT_ALL)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_EXECUTE)->EnableWindow(FALSE);

	GetDlgItem(IDC_BUTTON_SEND_CMD)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_GET_CURRENT_STATE)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_SET_STATE)->EnableWindow(FALSE);

	GetDlgItem(IDC_BUTTON_SET_ADDR)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_DOWNLOAD)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_VERIFY_SHA1)->EnableWindow(FALSE);

	GetDlgItem(IDC_BUTTON_READ_FLASH)->EnableWindow(FALSE);

	m_mResult.SetWindowTextA(_T(""));
	m_mTestResult.SetWindowTextA(_T(""));


	for (p = buf; *p; p += (_tcslen(p) + 1)) {
		LPCTSTR sDrivePath = p;
		str = sDrivePath;
		str.Delete(2, 1);
		uType = GetDriveType(str);
		if (uType == DRIVE_REMOVABLE) {
			SetDlgItemText(IDC_COMBO_PORT, str);
			exist = 1;
		}
	}

	if (exist == 0) {
		AfxMessageBox(_T("û�м�⵽ SD ��, �����²��"));
	}
}


void CPublish_ToolDlg::OnClickedButtonOpenClose()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
		// TODO: �ڴ���ӿؼ�֪ͨ����������
	CString sDrive, sInterface;
	ULONG ulRet;

	GetDlgItemText(IDC_COMBO_PORT, sDrive);
	if (sDrive.IsEmpty()) // pan fu 
	{
		AfxMessageBox(_T("�������̷���"));
		return;
	}
	sInterface = "SECOM.SCT";
	if (sInterface.IsEmpty())
	{
		AfxMessageBox(_T("�����ýӿ��ļ���"));
		return;
	}
	m_pMeth->SetInterfaceName(sInterface);

	if (ulRet = m_pMeth->OpenDevice(sDrive, NULL, &hDevice))
	{
		AfxMessageBox(_T("���豸ʧ�ܣ�"));
		return;
	}

	ShowMessageString(_T("���豸�ɹ�"));

	GetDlgItem(IDC_BUTTON_SEND_CMD)->EnableWindow(TRUE);
	GetDlgItem(IDC_BUTTON_FS_SELECT_ALL)->EnableWindow(TRUE);
	GetDlgItem(IDC_BUTTON_BUSNISS_SELECT_ALL)->EnableWindow(TRUE);
	GetDlgItem(IDC_BUTTON_IKI_SELECT_ALL)->EnableWindow(TRUE);
	GetDlgItem(IDC_BUTTON_POL_SELECT_ALL)->EnableWindow(TRUE);
	GetDlgItem(IDC_BUTTON_EXECUTE)->EnableWindow(TRUE);

	GetDlgItem(IDC_BUTTON_SET_ADDR)->EnableWindow(TRUE);
	GetDlgItem(IDC_BUTTON_DOWNLOAD)->EnableWindow(TRUE);
	GetDlgItem(IDC_BUTTON_VERIFY_SHA1)->EnableWindow(TRUE);

	GetDlgItem(IDC_BUTTON_READ_FLASH)->EnableWindow(TRUE);
}


void CPublish_ToolDlg::OnBnClickedButtonExecute()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������

	//��ÿ��ִ��ʱ, ��Ҫ�������ָ���б�   by Huihh 2018.05.18
	g_sSupportCmdList = "";


	pWinThread = AfxBeginThread(Thread_Execute, &ThreadInfo);

	if (pWinThread == NULL)
	{
		AfxMessageBox(_T("Begin Thread Failed, Please Try Again"));
		return;
	}


	GetDlgItem(IDC_BUTTON_FS_SELECT_ALL)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_BUSNISS_SELECT_ALL)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_IKI_SELECT_ALL)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_POL_SELECT_ALL)->EnableWindow(FALSE);

	GetDlgItem(IDC_BUTTON_SEND_CMD)->EnableWindow(FALSE);

	GetDlgItem(IDC_BUTTON_GET_CURRENT_STATE)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_SET_STATE)->EnableWindow(FALSE);

	GetDlgItem(IDC_BUTTON_EXECUTE)->EnableWindow(FALSE);

}


UINT CPublish_ToolDlg::Thread_Execute(LPVOID pPram)
{
	CPublish_ToolDlg *pDlg = ((threadInfo *)pPram)->pDlg;
	pDlg->Process_Execute(pPram);

	return 0;
}





int CPublish_ToolDlg::Process_Execute(LPVOID pPram)
{
	//Fs --8--
	if (m_mCreateFile.GetCheck() == 1) {
		SKF_CREATE_FILE();
		m_mCreateFile.SetCheck(0);
	}
	if (m_mCreateMF.GetCheck() == 1) {
		SKF_CREATE_MF();
		m_mCreateMF.SetCheck(0);
	}
	if (m_mCreateDF1.GetCheck() == 1) {
		SKF_CREATE_DF0();
		m_mCreateDF1.SetCheck(0);
	}
	if (m_mCreateEF1.GetCheck() == 1) {
		SKF_CREATE_EF0();
		m_mCreateEF1.SetCheck(0);
	}
	if (m_mDeleteFile.GetCheck() == 1) {
		SKF_DELET_FILE();
		m_mDeleteFile.SetCheck(0);
	}
	if (m_mSelectFile.GetCheck() == 1) {
		SKF_SELECT_FILE();
		m_mSelectFile.SetCheck(0);
	}
	if (m_mSelectMF.GetCheck() == 1) {
		SKF_SELECT_MF();
		m_mSelectMF.SetCheck(0);
	}
	if (m_mSelectDF1.GetCheck() == 1) {
		SKF_SELECT_DF0();
		m_mSelectDF1.SetCheck(0);
	}
	if (m_mSelectEF1.GetCheck() == 1) {
		SKF_SELECT_EF0();
		m_mSelectEF1.SetCheck(0);
	}
	if (m_mReadFile.GetCheck() == 1) {
		SKF_READ_FILE();
		m_mReadFile.SetCheck(0);
	}
	if (m_mWriteFile.GetCheck() == 1) {
		SKF_WRITE_FILE();
		m_mWriteFile.SetCheck(0);
	}
	if (m_mGetAppList.GetCheck() == 1) {
		SKF_GET_DF_LIST();
		m_mGetAppList.SetCheck(0);
	}
	if (m_mGetFileList.GetCheck() == 1) {
		SKF_GET_EF_LIST();
		m_mGetFileList.SetCheck(0);
	}
	if (m_mGetDevInfo.GetCheck() == 1) {
		SKF_GET_DEV_INFO();
		m_mGetDevInfo.SetCheck(0);
	}
	if (m_mSetDevInfo.GetCheck() == 1) {
		SKF_SET_DEV_INFO();
		m_mSetDevInfo.SetCheck(0);
	}


	if (m_mGetRand.GetCheck() == 1) {
		SKF_GET_RAND();
		m_mGetRand.SetCheck(0);
	}
	if (m_mDeviceAuth.GetCheck() == 1) {
		SKF_DEVICE_AUTH();
		m_mDeviceAuth.SetCheck(0);
	}
	if (m_mModDevAutKey.GetCheck() == 1) {
		SKF_MODIFY_DEV_AUTH_KEY();
		m_mModDevAutKey.SetCheck(0);
	}
	if (m_mModifyPin.GetCheck() == 1) {
		SKF_MODIFY_PIN();
		m_mModifyPin.SetCheck(0);
	}
	if (m_mVerifyPin.GetCheck() == 1) {
		SKF_VERIFY_PIN();
		m_mVerifyPin.SetCheck(0);
	}
	if (m_mUnBlockResetPin.GetCheck() == 1) {
		SKF_UNLOCK_RESET_PIN();
		m_mUnBlockResetPin.SetCheck(0);
	}
	if (m_mGetSessionKey.GetCheck() == 1) {
		SKF_GET_SESSION_KEY();
		m_mGetSessionKey.SetCheck(0);
	}
	if (m_mGenRSAKey.GetCheck() == 1) {
		SKF_GENARATE_RSA_KEY_PAIR();
		m_mGenRSAKey.SetCheck(0);
	}
	if (m_mGenSM2Key.GetCheck() == 1) {
		SKF_GENARATE_SM2_KEY_PAIR();
		m_mGenSM2Key.SetCheck(0);
	}
	if (m_mGetRSAKey.GetCheck() == 1) {
		SKF_EXPORT_PSA_PUB_KEY();
		m_mGetRSAKey.SetCheck(0);
	}
	if (m_mGetSM2Key.GetCheck() == 1) {
		SKF_EXPORT_SM2_PUB_KEY();
		m_mGetSM2Key.SetCheck(0);
	}
	if (m_mImportPubKey.GetCheck() == 1) {
		SKF_IMPORT_PUBKEY();
		m_mImportPubKey.SetCheck(0);
	}
	if (m_mImportKey.GetCheck() == 1) {
		SKF_IMPORT_KEY();
		m_mImportKey.SetCheck(0);
	}
	if (m_mDeletKey.GetCheck() == 1) {
		SKF_DELET_KEY();
		m_mDeletKey.SetCheck(0);
	}
	if (m_mSessionKeyAlg.GetCheck() == 1) {
		SKF_SESSION_KEY_ALG();
		m_mSessionKeyAlg.SetCheck(0);
	}
	if (m_mSetMode.GetCheck() == 1) {
		SKF_SET_MODE();
		m_mSetMode.SetCheck(0);
	}
	if (m_mSymMac.GetCheck() == 1) {
		SKF_SYM_MAC();
		m_mSymMac.SetCheck(0);
	}
	if (m_mSymEncrypt.GetCheck() == 1) {
		SKF_SYM_ENCRYPT();
		m_mSymEncrypt.SetCheck(0);
	}
	if (m_mSymDecrypt.GetCheck() == 1) {
		SKF_SYM_DECRYPT();
		m_mSymDecrypt.SetCheck(0);
	}
	if (m_mSM3Hash.GetCheck() == 1) {
		SKF_HASH_SM3();
		m_mSM3Hash.SetCheck(0);
	}
	if (m_mSM2Sign.GetCheck() == 1) {
		SKF_SM2_SIGN();
		m_mSM2Sign.SetCheck(0);
	}
	if (m_mSM2Vertfy.GetCheck() == 1) {
		SKF_SM2_VERTFY();
		m_mSM2Vertfy.SetCheck(0);
	}
	if (m_mActivateCos.GetCheck() == 1) {
		SKF_ACTIVATE_COS();
		m_mActivateCos.SetCheck(0);
	}

	
	SKF_Functional_Testing();


	ShowMessageString(_T("��ǰ״̬֧�ֵ�ָ�"));
	ShowMessageString(g_sSupportCmdList);

	ShowMessageString(_T("ִ�����"));

	AfxMessageBox(_T("ִ�����"));

	GetDlgItem(IDC_BUTTON_FS_SELECT_ALL)->EnableWindow(TRUE);
	GetDlgItem(IDC_BUTTON_BUSNISS_SELECT_ALL)->EnableWindow(TRUE);
	GetDlgItem(IDC_BUTTON_IKI_SELECT_ALL)->EnableWindow(TRUE);
	GetDlgItem(IDC_BUTTON_POL_SELECT_ALL)->EnableWindow(TRUE);

	GetDlgItem(IDC_BUTTON_SEND_CMD)->EnableWindow(TRUE);

	GetDlgItem(IDC_BUTTON_GET_CURRENT_STATE)->EnableWindow(TRUE);
	GetDlgItem(IDC_BUTTON_SET_STATE)->EnableWindow(TRUE);


	GetDlgItem(IDC_BUTTON_EXECUTE)->EnableWindow(TRUE);




	return 0;
}









//ÿ��ָ��֮ǰ�ȷ��� FIRST_CMD ָ��, Ȼ���ٷ��Ͷ�Ӧָ��
#define FIRST_CMD										"3305000000"  

//���˵��ϼ�Ŀ¼
#define SELECT_FATHER								   "00A4000000"  // "00A40000020000"  

/* fs  */
#define    	SKF_CREATE_FILE_MF_CMD						"84E00000ED"
#define    	SKF_CREATE_FILE_DF0_CMD						"84E0010088"
#define    	SKF_DELET_FILE_DF0_CMD	                    "84EE0100020000"
#define    	SKF_CREATE_FILE_DF1_CMD			            "84E00100840000061010FFFFFFFF02030405060708090203040506070809020304050607080902030405060708000001020304050607000102030405060700010203040506070001020304050607020201FF0807060504030201080706050403020108070605040302010807060504030201050501FF0C0C0A0000000000000000FFFFFFFFFFFFFFFF"
//#define    	SKF_CREATE_FILE_DF1_CMD					"84E00100880000061010FFFFFFFF02030405060708090203040506070809020304050607080902030405060708000001020304050607000102030405060700010203040506070001020304050607000000000000000201FF0807060504030201080706050403020108070605040302010807060504030201000000000000000501FF0C0C0AFFFFFFFFFFFFFFFF"
#define    	SKF_DELET_FILE_DF1_CMD	                    "84EE0100020001"
#define    	SKF_CREATE_FILE_DF2_CMD                     "84E00100840000061010FFFFFFFF0405060708090A0B0405060708090A0B0405060708090A0B0405060708090A000001020304050607000102030405060700010203040506070001020304050607020201FF0807060504030201080706050403020108070605040302010807060504030201050501FF0C0C0A0000000000000000FFFFFFFFFFFFFFFF"
//#define    	SKF_CREATE_FILE_DF2_CMD					"84E00100880000061010FFFFFFFF0405060708090A0B0405060708090A0B0405060708090A0B0405060708090A000001020304050607000102030405060700010203040506070001020304050607000000000000000201FF0807060504030201080706050403020108070605040302010807060504030201000000000000000501FF0C0C0AFFFFFFFFFFFFFFFF"
#define    	SKF_DELET_FILE_DF2_CMD	                    "84EE0100020002"
#define     SKF_CREATE_FILE_EF0_CMD                      "84E0020029"
#define    	SKF_DELET_FILE_EF0_CMD                       "84EE0200020000"
#define     SKF_CREATE_FILE_EF1_CMD                      "84E0020029000100FF1010FFFFFF0101010101010101010101010101010101010101010101010101010101010200"
#define    	SKF_DELET_FILE_EF1_CMD                       "84EE0200020001"
#define     SKF_CREATE_FILE_EF2_CMD                      "84E0020029000200FF1010FFFFFF0101010101010101010101010101010101010101010101010101010101010300"
#define    	SKF_DELET_FILE_EF2_CMD                       "84EE0200020002"
#define    	SKF_SELECT_FILE_CMD							"00A400000411223344"
#define    	SKF_READ_FILE_CMD							"00B0000008"
#define    	SKF_WRITE_FILE_CMD							"00D60000082122232425262728"
#define    	SKF_GET_DF_LIST_CMD						    "8034000021"  
#define    	SKF_GET_EF_LIST_CMD						    "8034010061"  
#define    	SKF_GET_DEV_INFO_CMD						"80EA0000E4"
#define    	SKF_SET_DEV_INFO_CMD						"84EC010020"
#define     SKF_GET_FILE_INFO_CMD                       "80EA020038"
#define     SKF_GET_APP_INFO_CMD                        "80EA0100FF"



#define    	SKF_GET_RAND_CMD							"0084000008"
#define    	SKF_DEVICE_AUTH_CMD							"0082000010"
#define    	SKF_MODIFY_DEVICE_AUTH_KEY_CMD				"0024020020"
#define    	SKF_MODIFY_PIN_CMD							"0024010080"
#define    	SKF_GET_SESSION_KEY_CMD						"004700000411223344"  //TODO
#define    	SKF_GENARATE_RSA_KEY_PAIR_CMD				"0046000002040080"
#define    	SKF_GENARATE_SM2_KEY_PAIR_CMD				"0046010002010040"
#define    	SKF_GET_PUB_KEY_CMD							"80E600000411223344"  //TODO
#define    	SKF_GET_RSA_PUB_KEY_CMD                     "80E61B0080"
#define    	SKF_VERIFY_PIN_CMD							"0020000180" 
#define    	SKF_UNLOCK_RESET_PIN_CMD					"002C000080" 
#define    	SKF_IMPORT_PUBKEY_CMD						"80E700000411223344"   //TODO
#define    	SKF_IMPORT_KEY_CMD							"84D400000411223344"    //TODO
#define    	SKF_DELET_KEY_CMD							"844000000411223344"     //TODO
#define    	SKF_SESSION_KEY_ALG_CMD						"C0D00000"
#define    	SKF_SET_MODE_CMD							"80D200"
#define    	SKF_SYM_MAC_CMD								"80D700000411223344"
#define    	SKF_SYM_ENCRYPT_CMD							"80D800000411223344"
#define    	SKF_SYM_DECRYPT_CMD							"80D900000411223344"
#define    	SKF_DISCONNECT_DEV_CMD						"FFFF00000411223344"


/* IKI --15-- */
#define    	IKI_IMPORT_ENABLE_CMD						"9002000000"
#define    	IKI_IMPORT_PUBKEY_MATRIX_START_CMD			"10E7000000"
#define    	IKI_IMPORT_PUBKEY_MATRIX_END_CMD			"90E7000000"
#define    	IKI_GET_PUBKEY_MATRIX_LEN_CMD				"90E5000000"
#define    	IKI_EXPORT_PUBKEY_MATRIX_CMD				"90E6000000"
#define    	IKI_IMPORT_IDENTITY_CMD						"9404000000"
#define    	IKI_EXPORT_IDENTITY_CMD						"9008000000"
#define    	IKI_IMPORT_UID_START_CMD					"10E8000000"
#define    	IKI_IMPORT_UID_END_CMD						"90E8000000"
#define    	IKI_GET_UID_LEN_CMD							"90EA000000"
#define    	IKI_EXPORT_UID_CMD							"90E9000000"
#define    	IKI_GENERATE_KEY_PAIR_CMD					"900C000000"
#define    	IKI_GET_KEYPAIR_PUBKEY_CMD					"9010000000"
#define    	IKI_IDENTITY_CALC_PUBKEY_CMD				"9012000000"
#define    	IKI_IMPORT_KEY_PAIR_CMD						"941800000411223344"






//ָ����ʾ��־λ
#define		FIRST_FLAG	1
#define     SKF_FLAG    1



void CPublish_ToolDlg::SKF_CREATE_FILE()
{
	ShowMessageString(_T("�����ļ�"));

	SKF_CREATE_MF();

	SKF_CREATE_DF0();

	SKF_VERIFY_PIN();

	//DF0�´���EF
	SKF_CREATE_EF0();
	SKF_CREATE_EF1();
	SKF_CREATE_EF2();

	ShowMessageString(_T("�����ļ��ɹ�"));
}

void CPublish_ToolDlg::SKF_CREATE_MF()
{
	ShowMessageString(_T("����MF�ļ�"));

	CString sCmd;

	sCmd = SKF_CREATE_FILE_MF_CMD;

	sCmd += "3F0006100000000000";

	/** MF��Ϣͷ ��ʼ *********************************************************************/
	//64 + 64 + 16 + 32 + 32 + 2 + 2 + 4 + 4 + 4 + 4
	sCmd += "5A686F6E675969546F6E6720436F6D70616E79000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; //Manufacturer
	sCmd += "5A686F6E675969546F6E6720436F6D70616E79000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; //Issuer
	sCmd += "413520434F5320323031382E30362E00"; //Model
	sCmd += "413520434F5320323031382E30362E0000000000000000000000000000000000"; //Label
	sCmd += "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"; //SerialNumber
	sCmd += "0101"; //HWVersion
	sCmd += "0101"; //FirmwareVersion
	sCmd += "00112233"; //AlgSymCap
	sCmd += "00112233"; //AlgAsymCap
	sCmd += "00112233"; //AlgHashCap
	sCmd += "00112233"; //DevAuthAlgId
	/** MF��Ϣͷ ���� *********************************************************************/

	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("CREATE MF ERROR");
		ShowMessageString(sw);
		return;
	}
	ShowMessageString(_T("����MF�ļ��ɹ�"));


}

void CPublish_ToolDlg::SKF_CREATE_DF0()
{
	ShowMessageString(_T("����DF0�ļ�"));

	CString sCmd;

	//ѡ��MF
	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);
	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);

	SKF_DEVICE_AUTH();

	sCmd = "84E001007C";

	//�ļ���ID
	sCmd += "DF00";

	//DF���ļ��ĸ���
	sCmd += "06";

	sCmd += "1010FFFFFFFF";

	//Ӧ������
	sCmd += "0102030405060708010203040506070801020304050607080102030405060700";

	//sopin��ϣֵ
	sCmd += "0001020304050607000102030405060700010203040506070001020304050607";

	//����ԱPIN���Դ���
	//sCmd += "0000000000000002";
	//sCmd += "0202";
	sCmd += "02000000";

	//��С/�����ԱPIN����
	sCmd += "01FF";

	// user pin��ϣֵ
	sCmd += "0807060504030201080706050403020108070605040302010807060504030201";

	//�û�PIN���Դ���
	//sCmd += "0000000000000005";
	//sCmd += "0505";
	sCmd += "05000000";

	//��С/��USERPIN����
	sCmd += "01FF";

	sCmd += "0C0C0A";

	sCmd += "FFFFFFFF";


	//���ڼ�¼P11��Ӧtoken��������״̬��־λ�������Ƿ�Ϊ��ʼ��PIN���Ƿ��������Ƿ�߱���������������Ƿ���Ӳ��ʱ�ӵȡ�
	//sCmd += "0000000000000000";
		
	//sCmd += "FFFFFFFFFFFFFFFF";

	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("CREATE DF0 ERROR");
		ShowMessageString(sw);
		return;
	}
	ShowMessageString(_T("����DF0�ļ��ɹ�"));
}

void CPublish_ToolDlg::SKF_CREATE_DF1()
{
	ShowMessageString(_T("����DF0�ļ�"));

	//ѡ��MF
	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);
	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);

	SKF_DEVICE_AUTH();

	
	sw = SendCommandGetValueOrSW(SKF_CREATE_FILE_DF1_CMD, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("CREATE DF1 ERROR");
		ShowMessageString(sw);
		return;
	}
	ShowMessageString(_T("����DF1�ļ��ɹ�"));
}

void CPublish_ToolDlg::SKF_CREATE_DF2()
{
	ShowMessageString(_T("����DF0�ļ�"));

	//ѡ��MF
	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);
	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);

	SKF_DEVICE_AUTH();

	
	sw = SendCommandGetValueOrSW(SKF_CREATE_FILE_DF2_CMD, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("CREATE DF2 ERROR");
		ShowMessageString(sw);
		return;
	}
	ShowMessageString(_T("����DF2�ļ��ɹ�"));
}

void CPublish_ToolDlg::SKF_CREATE_EF0()
{
	ShowMessageString(_T("����EF0�ļ�"));

	CString sCmd;

	//ѡ��MF
	/*
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);
	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);

	//ѡ��DF0
	
	SendCommandGetValueOrSW("00A4010002DF00", FIRST_FLAG);*/

	sCmd = SKF_CREATE_FILE_EF0_CMD;

	//ID
	sCmd += "EF00";

	//file size
	sCmd += "000F";

	//read right��write right
	sCmd += "1010";

	sCmd += "FFFFFF";

	//filename
	sCmd += "0101010101010101010101010101010101010101010101010101010101010100";

	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("CREATE EF0 ERROR");
		ShowMessageString(sw);
		return;
	}
	ShowMessageString(_T("����EF0�ļ��ɹ�"));
}

void CPublish_ToolDlg::SKF_CREATE_EF1()
{
	ShowMessageString(_T("����EF1�ļ�"));

	SKF_SELECT_DF0();

	CString sCmd;
	sCmd = SKF_CREATE_FILE_EF0_CMD;

	//ID
	sCmd += "EF01";

	//file size
	sCmd += "000F";

	//read right��write right
	sCmd += "1010";

	sCmd += "FFFFFF";

	//filename
	sCmd += "0101010101010101010101010101010101010101010101010101010101010200";

	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("CREATE EF1 ERROR");
		ShowMessageString(sw);
		return;
	}
	ShowMessageString(_T("����EF1�ļ��ɹ�"));
}

void CPublish_ToolDlg::SKF_CREATE_EF2()
{
	ShowMessageString(_T("����EF2�ļ�"));

	SKF_SELECT_DF0();

	CString sCmd;
	sCmd = SKF_CREATE_FILE_EF0_CMD;

	//ID
	sCmd += "EF02";

	//file size
	sCmd += "000F";

	//read right��write right
	sCmd += "1010";

	sCmd += "FFFFFF";

	//filename
	sCmd += "0101010101010101010101010101010101010101010101010101010101010300";

	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("CREATE EF2 ERROR");
		ShowMessageString(sw);
		return;
	}
	ShowMessageString(_T("����EF2�ļ��ɹ�"));
}

void CPublish_ToolDlg::SKF_DELET_FILE()
{
	ShowMessageString(_T("ɾ���ļ�"));

	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);
	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);

	
	sw = SendCommandGetValueOrSW("84EE0000023F00", SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("DELET FILE ERROR");
		ShowMessageString(sw);
		return;
	}

	/*SKF_DELET_DF0();
	SKF_DELET_DF1();
	SKF_DELET_DF2();*/
	ShowMessageString(_T("ɾ���ļ��ɹ�"));
}

void CPublish_ToolDlg::SKF_DELET_DF0()
{
	ShowMessageString(_T("ɾ��DF0�ļ�"));
	//CString sCmd;

	//ѡ��MF
	/*
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);
	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);

	SKF_DEVICE_AUTH();

	//ѡ��DF0
	
	//sCmd = "00A4010002DF00";
	SendCommandGetValueOrSW("00A4010002DF00", FIRST_FLAG);*/

	
	sw = SendCommandGetValueOrSW("84EE01011F01020304050607080102030405060708010203040506070801020304050607", SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("DELET DF0 ERROR");
		ShowMessageString(sw);
		return;
	}
	ShowMessageString(_T("ɾ��DF0�ļ��ɹ�"));
}

void CPublish_ToolDlg::SKF_DELET_DF1()
{
	ShowMessageString(_T("ɾ��DF0�ļ�"));
	//CString sCmd;

	//ѡ��MF
	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);
	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);

	SKF_DEVICE_AUTH();

	//ѡ��DF1
	
	//sCmd = "00A4010002DF00";
	SendCommandGetValueOrSW("00A4010002DF01", FIRST_FLAG);

	
	sw = SendCommandGetValueOrSW(SKF_DELET_FILE_DF1_CMD, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("DELET DF1 ERROR");
		ShowMessageString(sw);
		return;
	}
	ShowMessageString(_T("ɾ��DF1�ļ��ɹ�"));
}

void CPublish_ToolDlg::SKF_DELET_DF2()
{
	ShowMessageString(_T("ɾ��DF2�ļ�"));
	//CString sCmd;

	//ѡ��MF
	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);
	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);

	SKF_DEVICE_AUTH();

	//ѡ��DF2
	
	//sCmd = "00A4010002DF00";
	SendCommandGetValueOrSW("00A4010002DF02", FIRST_FLAG);

	
	sw = SendCommandGetValueOrSW(SKF_DELET_FILE_DF2_CMD, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("DELET DF2 ERROR");
		ShowMessageString(sw);
		return;
	}
	ShowMessageString(_T("ɾ��DF2�ļ��ɹ�"));
}

void CPublish_ToolDlg::SKF_DELET_EF0()
{
	ShowMessageString(_T("ɾ��EF0�ļ�"));
	//CString sCmd;

	//ѡ��MF
	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);
	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);

	//ѡ��DF0
	
	SendCommandGetValueOrSW("00A4010002DF00", FIRST_FLAG);

	//ѡ��EF0
	/*
	//sCmd = "00A4010002DF00";
	SendCommandGetValueOrSW("00A4010102EF00", FIRST_FLAG);*/

	
	sw = SendCommandGetValueOrSW(SKF_DELET_FILE_EF0_CMD, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("DELET EF0 ERROR");
		ShowMessageString(sw);
		return;
	}
	ShowMessageString(_T("ɾ��EF0�ļ��ɹ�"));
}

void CPublish_ToolDlg::SKF_DELET_EF1()
{
	ShowMessageString(_T("ɾ��EF1�ļ�"));
	//CString sCmd;

	//ѡ��MF
	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);
	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);

	//ѡ��DF0
	
	SendCommandGetValueOrSW("00A4010002DF00", FIRST_FLAG);

	//ѡ��EF1
	
	//sCmd = "00A4010002DF00";
	SendCommandGetValueOrSW("00A4010102EF01", FIRST_FLAG);

	
	sw = SendCommandGetValueOrSW(SKF_DELET_FILE_EF1_CMD, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("DELET EF1 ERROR");
		ShowMessageString(sw);
		return;
	}
	ShowMessageString(_T("ɾ��EF1�ļ��ɹ�"));
}

void CPublish_ToolDlg::SKF_DELET_EF2()
{
	ShowMessageString(_T("ɾ��EF1�ļ�"));
	//CString sCmd;

	//ѡ��MF
	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);
	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);

	//ѡ��DF0
	
	SendCommandGetValueOrSW("00A4010002DF00", FIRST_FLAG);

	//ѡ��EF2
	
	//sCmd = "00A4010002DF00";
	SendCommandGetValueOrSW("00A4010102EF02", FIRST_FLAG);

	
	sw = SendCommandGetValueOrSW(SKF_DELET_FILE_EF2_CMD, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("DELET EF2 ERROR");
		ShowMessageString(sw);
		return;
	}
	ShowMessageString(_T("ɾ��EF2�ļ��ɹ�"));
}

void CPublish_ToolDlg::SKF_SELECT_FILE()
{
	ShowMessageString(_T("ѡ���ļ�"));

	//ѡ��MF
	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);
	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);

	SKF_DEVICE_AUTH();

	//ѡ��DF0
	
	SendCommandGetValueOrSW("00A4010002DF00", FIRST_FLAG);

	SKF_VERIFY_PIN();

	//ѡ��DF0�µ�EF0�ļ�
	
	SendCommandGetValueOrSW("00A4010102EF00", FIRST_FLAG);

	ShowMessageString(_T("ѡ���ļ��ɹ�"));
}

void CPublish_ToolDlg::SKF_SELECT_MF()
{
	ShowMessageString(_T("ѡ���ļ�MF"));

	//ѡ��MF
	
	sw = SendCommandGetValueOrSW("00A4000000", FIRST_FLAG);
	/*if (sw != "9000")
	{
		ShowMessageString("SELECT MF ERROR");
		ShowMessageString(sw);
		return;
	}*/
	//
	//SendCommandGetValueOrSW("00A4000000", FIRST_FLAG);

	ShowMessageString(_T("ѡ���ļ�MF�ɹ�"));
}

void CPublish_ToolDlg::SKF_SELECT_DF0()
{
	ShowMessageString(_T("ѡ���ļ�DF0"));

	//ѡ��MF
	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);
	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);

	//ѡ��DF0
	
	sw = SendCommandGetValueOrSW("00A40200200102030405060708010203040506070801020304050607080102030405060700", SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("SELECT DF0 ERROR");
		ShowMessageString(sw);
		return;
	}


	ShowMessageString(_T("ѡ���ļ�DF0�ɹ�"));
}

void CPublish_ToolDlg::SKF_SELECT_EF0()
{
	ShowMessageString(_T("ѡ���ļ�EF0"));

	//ѡ��DF0�µ�EF0�ļ�
	
	sw = SendCommandGetValueOrSW("00A40201200101010101010101010101010101010101010101010101010101010101010100", SKF_FLAG);

	ShowMessageString(_T("ѡ���ļ�EF0�ɹ�"));
}

void CPublish_ToolDlg::SKF_READ_FILE()
{
	ShowMessageString(_T("��ȡ�ļ�"));

	
	sw = SendCommandGetValueOrSW(SKF_READ_FILE_CMD, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("READ FILE ERROR");
		ShowMessageString(sw);
		return;
	}
	ShowMessageString(sValue);
	ShowMessageString(_T("��ȡ�ļ��ɹ�"));
}

void CPublish_ToolDlg::SKF_WRITE_FILE()
{
	ShowMessageString(_T("д���ļ�"));

	
	sw = SendCommandGetValueOrSW(SKF_WRITE_FILE_CMD, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("WRITE FILE ERROR");
		ShowMessageString(sw);
		return;
	}
	ShowMessageString(_T("д���ļ��ɹ�"));
}

void CPublish_ToolDlg::SKF_GET_DF_LIST()
{
	ShowMessageString(_T("��ȡӦ��(DF)�б�"));

	//ѡ��MF
	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);
	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);

	
	sw = SendCommandGetValueOrSW(SKF_GET_DF_LIST_CMD, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("GET DF LIST ERROR");
		ShowMessageString(sw);
		return;
	}
	ShowMessageString(sValue);
	ShowMessageString(_T("��ȡӦ��(DF)�б�ɹ�"));
}

void CPublish_ToolDlg::SKF_GET_EF_LIST()
{
	ShowMessageString(_T("��ȡ�ļ�(EF)�б�"));

	//ѡ��MF
	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);
	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);

	//ѡ��DF0
	
	SendCommandGetValueOrSW("00A4010002DF00", FIRST_FLAG);

	
	sw = SendCommandGetValueOrSW(SKF_GET_EF_LIST_CMD, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("GET EF LIST ERROR");
		ShowMessageString(sw);
		return;
	}
	ShowMessageString(sValue);
	ShowMessageString(_T("��ȡ�ļ�(EF)�б�ɹ�"));
}

void CPublish_ToolDlg::SKF_GET_DEV_INFO()
{
	ShowMessageString(_T("��ȡ�豸��Ϣ"));

	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);
	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);

	

	sw = SendCommandGetValueOrSW(SKF_GET_DEV_INFO_CMD, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("GET DEV INFO ERROR");
		ShowMessageString(sw);
		return;
	}
	//ShowMessageString(sValue);
	ShowMessageString(_T("��ȡ�豸��Ϣ�ɹ�"));
}

void CPublish_ToolDlg::SKF_SET_DEV_INFO()
{
	ShowMessageString(_T("�����豸��Ϣ"));

	CString sLable = SKF_SET_DEV_INFO_CMD;
	CString sTemp;
	BYTE asLable[32] = { "aaaaaaaa" };//{ 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };

	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);
	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);

	for (int i = 0; i< 32; i++)
	{
		sTemp.Format("%02x", asLable[i]);
		sLable += sTemp;
	}
	sLable.MakeUpper();

	
	sw = SendCommandGetValueOrSW(sLable, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("SET DEV INFO ERROR");
		ShowMessageString(sw);
		return;
	}
	//ShowMessageString(sValue);
	ShowMessageString(_T("�����豸��Ϣ�ɹ�"));
}

void CPublish_ToolDlg::SKF_GET_FILE_INFO()
{
	ShowMessageString(_T("��ȡ�ļ���Ϣ"));

	
	sw = SendCommandGetValueOrSW("80EA02002C", SKF_FLAG);
	//sw = SendCommandGetValueOrSW(SKF_GET_FILE_INFO_CMD, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("SKF GET FILE INFO ERROR");
		ShowMessageString(sw);
		return;
	}
	ShowMessageString(_T("��ȡ�ļ���Ϣ�ɹ�"));
}

void CPublish_ToolDlg::SKF_GET_APP_INFO()
{
	ShowMessageString(_T("��ȡӦ����Ϣ"));

	//ѡ��MF
	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);
	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);

	//ѡ��DF0
	
	SendCommandGetValueOrSW("00A4010002DF00", FIRST_FLAG);

	
	sw = SendCommandGetValueOrSW(SKF_GET_APP_INFO_CMD, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("GET APP INFO ERROR");
		ShowMessageString(sw);
		return;
	}
	ShowMessageString(_T("��ȡӦ����Ϣ�ɹ�"));
}



void CPublish_ToolDlg::SKF_GET_RAND()
{
	ShowMessageString(_T("ȡ�����"));
	CString sCmd = "00840000";

	sCmd += "08";

	//sCmd += "000102";

	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("GET RAND ERROR");
		ShowMessageString(sw);
		return;
	}
	ShowMessageString(_T("ȡ������ɹ�"));
}

void CPublish_ToolDlg::SKF_DEVICE_AUTH()
{
	ShowMessageString(_T("�豸��֤"));

	CString sAuthVal, sRandom8, sTemp;
	BYTE authPlainData[16] = { 0 };
	BYTE authCipherData[16] = { 0 };
	BYTE asDevAuthKey[16] = {0};
	//BYTE asDevAuthKey[16] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };

	sAuthVal = SKF_DEVICE_AUTH_CMD;
	memcpy(asDevAuthKey, g_aCurDevAuthKey, 16);

	//ѡ��MF
	/*
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);
	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);*/

	//��ȡ�����
	
	sw = SendCommandGetValueOrSW(SKF_GET_RAND_CMD, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("GET RAND ERROR");
		ShowMessageString(sw);
		return;
	}
	
	//sm4���������
	CstringToByte(sValue, authPlainData);
	Crypto_ECB_SM4(authPlainData, 16, asDevAuthKey, 1, authCipherData);
	for (int i = 0; i< 16; i++)
	{
		sTemp.Format("%02x", authCipherData[i]);
		//sRandom8 += sTemp;
		sAuthVal += sTemp;
	}
	//sRandom8.MakeUpper();
	sAuthVal.MakeUpper();

	Crypto_ECB_SM4(authCipherData, 16, asDevAuthKey, 0, authPlainData);
	for (int i = 0; i< 16; i++)
	{
		sTemp.Format("%02x", authPlainData[i]);
		sRandom8 += sTemp;
	}

	//�����豸��֤
	//sAuthVal += sRandom8;
	
	sw = SendCommandGetValueOrSW(sAuthVal, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("DEVICE AUTH ERROR");
		ShowMessageString(sw);
		return;
	}

	ShowMessageString(_T("�豸��֤�ɹ�"));
}

void CPublish_ToolDlg::SKF_MODIFY_DEV_AUTH_KEY()
{
	ShowMessageString(_T("�޸��豸��֤��Կ"));

	BYTE asNewDevAuthKey[16] = { 0 };
	BYTE changeBuf[32] = { 0 };
	BYTE changeCipBuf[32] = { 0 };
	CString sAuthVal, sTemp;

	memcpy(asNewDevAuthKey, g_aNewDevAuthKey, 16);

	/*
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);
	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);*/

	for (int i = 0; i < 32; i += 8)
	{
		(i % 16 == 0) ? (memcpy(&changeBuf[i], &g_aCurDevAuthKey[i / 16 * 8], 8)) : (memcpy(&changeBuf[i], &asNewDevAuthKey[i / 16 * 8], 8));
	}
	Crypto_ECB_SM4(changeBuf, 32, g_aCurDevAuthKey, 1, changeCipBuf);
	sAuthVal = SKF_MODIFY_DEVICE_AUTH_KEY_CMD;
	for (int i = 0; i< 32; i++)
	{
		sTemp.Format("%02x", changeCipBuf[i]);
		sAuthVal += sTemp;
	}
	sAuthVal.MakeUpper();

	
	sw = SendCommandGetValueOrSW(sAuthVal, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("MODIFY DEVICE AUTH KEY ERROR");
		ShowMessageString(sw);
		return;
	}
	memcpy(g_aCurDevAuthKey, asNewDevAuthKey, 16);

	ShowMessageString(_T("�޸��豸��֤��Կ�ɹ�"));
}

static int sign_random_gen(void* param, unsigned char *rnd, size_t size)
{

	unsigned char k[] = {
		/* sign */
		0x6C, 0xB2, 0x8D, 0x99, 0x38, 0x5C, 0x17, 0x5C,
		0x94, 0xF9, 0x4E, 0x93, 0x48, 0x17, 0x66, 0x3F,
		0xC1, 0x76, 0xD9, 0x25, 0xDD, 0x72, 0xB7, 0x27,
		0x26, 0x0D, 0xBA, 0xAE, 0x1F, 0xB2, 0xF9, 0x6F,
	};
	((void)param);
	((void)rnd);
	((void)size);

	memcpy(rnd, k, sizeof(k));

	return 0;
}

void CPublish_ToolDlg::SKF_ACTIVATE_COS()
{
	ShowMessageString(_T("оƬ����"));

	char *exponents[] =
	{
		"690C311442AE2619F1FDB0DB442E81D307E379B2F46F19BDB8BDDA6751098F97", /* d */
		"6F8C1C852B8AD075A28994448744F9C402894242BB43C2041A02B6D253C1C0AB", /* px */
		"6AAB32988DD81508FF971343F567274B0639DD09774A276EB92E2BD72B8BD5DC", /* py */
	};

	CString sAuthVal, sCmd, sTemp, sData;
	BYTE asNewDevAuthKey[16] = { 0 };
	BYTE changeBuf[32] = { 0 };
	BYTE changeCipBuf[32] = { 0 };
	BYTE asSm2Data[32 + 1 + 32] = {0};

	int ret;
	BYTE  user_id[] = "1234567812345678";
	BYTE output[32], r[32], s[32];
	
	sCmd = "0024030081";

	//SN/CPUID + BusinessID + �޸��豸��֤���� + ǰ��������ǩ��ֵ��������Ȩ˽Կǩ������

	sData = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

	sData += "01";

	memcpy(asNewDevAuthKey, g_aCurDevAuthKey, 16);
	for (int i = 0; i < 32; i += 8)
	{
		(i % 16 == 0) ? (memcpy(&changeBuf[i], &g_aCurDevAuthKey[i / 16 * 8], 8)) : (memcpy(&changeBuf[i], &asNewDevAuthKey[i / 16 * 8], 8));
	}
	Crypto_ECB_SM4(changeBuf, 32, g_aCurDevAuthKey, 1, changeCipBuf);
	for (int i = 0; i< 32; i++)
	{
		sTemp.Format("%02x", changeCipBuf[i]);
		sAuthVal += sTemp;
	}
	sAuthVal.MakeUpper();
	
	sData += sAuthVal;

	CstringToByte(sData, asSm2Data);
	
	sm2_context ctx;
	sm2_init(&ctx);
	mpi_read_string(&ctx.d, 16, exponents[0]);
	sm2_pubkey_read_string(&ctx, exponents[1], exponents[2]);

	ret = hash_msg_with_user_id(&ctx, asSm2Data, sizeof(asSm2Data), user_id, 16, output);
	if (ret != 0)
	{
		ShowMessageString("SKF ACTIVATE COS HASH ERROR");
		return;
	}

	ret = sm2_sign(&ctx, output, 0x20, r, s, sign_random_gen, NULL);
	if (ret != 0)
	{
		ShowMessageString("SKF ACTIVATE COS SIGN ERROR");
		return;
	}
	//ret = sm2_verify(&ctx, output, 0x20, r, s);

	for (int i = 0; i< 32; i++)
	{
		sTemp.Format("%02x", r[i]);
		sData += sTemp;
	}

	for (int i = 0; i< 32; i++)
	{
		sTemp.Format("%02x", s[i]);
		sData += sTemp;
	}
	sCmd += sData;
	sCmd.MakeUpper();

	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("SKF ACTIVATE COS ERROR");
		ShowMessageString(sw);
		return;
	}

	ShowMessageString(_T("����cos�ɹ�"));
}


void CPublish_ToolDlg::SKF_MODIFY_PIN()
{
	ShowMessageString(_T("�޸��û�PIN��"));

	CString sPinHash, sCmd, sTemp;
	BYTE asRandData[8] = { 0 };
	BYTE asOldPinHash[32] = { 0 };
	BYTE asNewPinHash[32] = { 0 };
	BYTE aPlainData[64] = { 0 };
	BYTE aCipherData[128] = { 0 };
	BYTE aRsaKeyMod[256] = { 0 };
	BYTE aRsaPubExp[4] = { 0x00, 0x01, 0x00, 0x01 };

	sPinHash = "0807060504030201080706050403020108070605040302010807060504030201";
	CstringToByte(sPinHash, asOldPinHash);
	sPinHash = "0405060700010203040506070001020304050607000102030405060700010203";
	CstringToByte(sPinHash, asNewPinHash);

	//��ȡ�����
	
	sw = SendCommandGetValueOrSW(SKF_GET_RAND_CMD, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("GET RAND ERROR");
		ShowMessageString(sw);
		return;
	}
	CstringToByte(sValue, asRandData);

	for (int i = 0; i < 32; i++) aPlainData[i] = asOldPinHash[i] ^ asNewPinHash[i];

	memcpy(&aPlainData[32], asNewPinHash, 32);

	for (int i = 0; i < 64; i++) aPlainData[i] ^= asRandData[i % 8];

	SKF_SELECT_DF0();

	//��ȡRSA��Կ
	
	sw = SendCommandGetValueOrSW(SKF_GET_RSA_PUB_KEY_CMD, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("EXPORT RSA PUB KEY ERROR");
		ShowMessageString(sw);
		return;
	}
	CstringToByte(sValue, &aRsaKeyMod[128]);

	rsa_pub_pkcs1_encrypt(aRsaKeyMod, aRsaPubExp, aPlainData, aCipherData, 64);
	sCmd = SKF_MODIFY_PIN_CMD;
	for (int i = 0; i< 128; i++)
	{
		sTemp.Format("%02x", aCipherData[i]);
		sCmd += sTemp;
	}
	sCmd.MakeUpper();

	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("MODIFY PIN ERROR");
		ShowMessageString(sw);
		return;
	}

	sVerPinHash = sPinHash;
	ShowMessageString(_T("�޸�PIN��ɹ�"));
}

void CPublish_ToolDlg::SKF_VERIFY_PIN()
{
	ShowMessageString(_T("��֤PIN��"));

	CString sCmd, sTemp;
	BYTE asRandData[8] = { 0 };
	//BYTE asPinHash[32] = {0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01};
	BYTE asPinHash[32] = {0};
	BYTE aPlainData[32] = { 0 };
	BYTE aCipherData[128] = { 0 };
	BYTE aRsaKeyMod[256] = {0};
	BYTE aRsaPubExp[4] = {0x00, 0x01, 0x00, 0x01};

	//��ȡ�����
	
	sw = SendCommandGetValueOrSW(SKF_GET_RAND_CMD, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("GET RAND ERROR");
		ShowMessageString(sw);
		return;
	}
	CstringToByte(sValue, asRandData);
	CstringToByte(sVerPinHash, asPinHash);
	/*memset(aPlainData, 0xff, 128);
	aPlainData[0] = 0x00;
	aPlainData[1] = 0x00;
	aPlainData[2+93] = 0x00;*/

	for (int i = 0; i < 32; i++)
	{
		//aPlainData[2 + 93 + 1 + i] = asPinHash[i] ^ asRandData[i % 8];
		aPlainData[i] = asPinHash[i] ^ asRandData[i % 8];
	}

	SKF_SELECT_DF0();

	//��ȡRSA��Կ
	
	sw = SendCommandGetValueOrSW(SKF_GET_RSA_PUB_KEY_CMD, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("EXPORT RSA PUB KEY ERROR");
		ShowMessageString(sw);
		return;
	}
	CstringToByte(sValue, &aRsaKeyMod[128]);
	//CstringToByte(sValue, aRsaKeyMod);

	/*for (int i = 0; i < 127; i += 4)
	{
		memcpy(&aRsaKeyMod[256-4-i], &aRsaKeyMod[i], 4);
		memset(&aRsaKeyMod[i], 0, 4);
		//aRsaKeyMod[128 + i] = aRsaKeyMod[127 - i];
		//aRsaKeyMod[127 - i] = 0;
	}*/

	int ret = rsa_pub_pkcs1_encrypt(aRsaKeyMod, aRsaPubExp, aPlainData, aCipherData, 32);
	sCmd = SKF_VERIFY_PIN_CMD;
	for (int i = 0; i< 128; i++)
	{
		sTemp.Format("%02x", aCipherData[i]);
		sCmd += sTemp;
	}
	sCmd.MakeUpper();

	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("VERIFY PIN ERROR");
		ShowMessageString(sw);
		return;
	}

	ShowMessageString(_T("��֤PIN��ɹ�"));
}

void CPublish_ToolDlg::SKF_VERIFY_SOPIN()
{
	ShowMessageString(_T("��֤PIN��"));

	CString sCmd, sTemp;
	BYTE asRandData[8] = { 0 };
	//BYTE asPinHash[32] = {0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01};
	BYTE asPinHash[32] = { 0 };
	BYTE aPlainData[32] = { 0 };
	BYTE aCipherData[128] = { 0 };
	BYTE aRsaKeyMod[256] = { 0 };
	BYTE aRsaPubExp[4] = { 0x00, 0x01, 0x00, 0x01 };

	//��ȡ�����
	
	sw = SendCommandGetValueOrSW(SKF_GET_RAND_CMD, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("GET RAND ERROR");
		ShowMessageString(sw);
		return;
	}
	CstringToByte(sValue, asRandData);
	CstringToByte(sVerSoPinHash, asPinHash);

	for (int i = 0; i < 32; i++) aPlainData[i] = asPinHash[i] ^ asRandData[i % 8];

	SKF_SELECT_DF0();

	//��ȡRSA��Կ
	
	sw = SendCommandGetValueOrSW(SKF_GET_RSA_PUB_KEY_CMD, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("EXPORT RSA PUB KEY ERROR");
		ShowMessageString(sw);
		return;
	}
	CstringToByte(sValue, &aRsaKeyMod[128]);

	int ret = rsa_pub_pkcs1_encrypt(aRsaKeyMod, aRsaPubExp, aPlainData, aCipherData, 32);
	sCmd = "0020000080";
	for (int i = 0; i< 128; i++)
	{
		sTemp.Format("%02x", aCipherData[i]);
		sCmd += sTemp;
	}
	sCmd.MakeUpper();

	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("VERIFY PIN ERROR");
		ShowMessageString(sw);
		return;
	}

	ShowMessageString(_T("��֤PIN��ɹ�"));
}

void CPublish_ToolDlg::SKF_UNLOCK_RESET_PIN()
{
	ShowMessageString(_T("������λPIN��"));

	CString sPinHash, sCmd, sTemp;
	BYTE asRandData[8] = { 0 };
	//BYTE asUerPinHash[32] = { 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01 };
	//BYTE asSoPinHash[32] =  { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
	BYTE asUerPinHash[32] = { 0  };
	BYTE asSoPinHash[32] = { 0 };
	BYTE aPlainData[64] = { 0 };
	BYTE aCipherData[128] = { 0 };
	BYTE aRsaKeyMod[256] = { 0 };
	BYTE aRsaPubExp[4] = { 0x00, 0x01, 0x00, 0x01 };

	sPinHash = "0807060504030201080706050403020108070605040302010807060504030201";
	CstringToByte(sPinHash, asUerPinHash);
	sPinHash = "0001020304050607000102030405060700010203040506070001020304050607";
	CstringToByte(sPinHash, asSoPinHash);

	//��ȡ�����
	
	sw = SendCommandGetValueOrSW(SKF_GET_RAND_CMD, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("GET RAND ERROR");
		ShowMessageString(sw);
		return;
	}
	CstringToByte(sValue, asRandData);

	for (int i = 0; i < 32; i++) aPlainData[i] = asSoPinHash[i] ^ asUerPinHash[i];

	memcpy(&aPlainData[32], asUerPinHash, 32);

	for (int i = 0; i < 64; i++) aPlainData[i] ^= asRandData[i % 8];

	SKF_SELECT_DF0();

	//��ȡRSA��Կ
	
	sw = SendCommandGetValueOrSW(SKF_GET_RSA_PUB_KEY_CMD, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("EXPORT RSA PUB KEY ERROR");
		ShowMessageString(sw);
		return;
	}
	CstringToByte(sValue, &aRsaKeyMod[128]);

	rsa_pub_pkcs1_encrypt(aRsaKeyMod, aRsaPubExp, aPlainData, aCipherData, 64);
	sCmd = SKF_UNLOCK_RESET_PIN_CMD;
	for (int i = 0; i< 128; i++)
	{
		sTemp.Format("%02x", aCipherData[i]);
		sCmd += sTemp;
	}
	sCmd.MakeUpper();

	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("UNLOCK RESET PIN ERROR");
		ShowMessageString(sw);
		return;
	}

	ShowMessageString(_T("������λPIN��ɹ�"));
}

//TODO
void CPublish_ToolDlg::SKF_GET_SESSION_KEY()
{
	ShowMessageString(_T("��ȡ�Ự��Կ"));
}

void CPublish_ToolDlg::SKF_GENARATE_RSA_KEY_PAIR()
{
	ShowMessageString(_T("����ģ��Ϊ1024b��RSAǩ����Կ��"));

	//��ȫ��������������rsa��Կ��
	
	sw = SendCommandGetValueOrSW("002201B80483000200", SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("GENARATE RSA KEY ERROR");
		ShowMessageString(sw);
		return;
	}

	
	sw = SendCommandGetValueOrSW(SKF_GENARATE_RSA_KEY_PAIR_CMD, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("GENARATE RSA KEY ERROR");
		ShowMessageString(sw);
		return;
	}
	ShowMessageString(_T("����ģ��Ϊ1024b��RSAǩ����Կ�Գɹ�"));
}

void CPublish_ToolDlg::SKF_GENARATE_SM2_KEY_PAIR()
{
	ShowMessageString(_T("����ģ��Ϊ64B��SM2��Կ��"));

	//��ȫ��������������SM2��Կ��
	
	sw = SendCommandGetValueOrSW("002201B80483000200", SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("1.GENARATE SM2 KEY ERROR");
		ShowMessageString(sw);
		return;
	}

	
	sw = SendCommandGetValueOrSW(SKF_GENARATE_SM2_KEY_PAIR_CMD, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("2.GENARATE SM2 KEY ERROR");
		ShowMessageString(sw);
		return;
	}
	ShowMessageString(_T("����ģ��Ϊ64B��SM2��Կ�Գɹ�"));
}

void CPublish_ToolDlg::SKF_EXPORT_PSA_PUB_KEY()
{
	ShowMessageString(_T("��ȡ RSA ��Կ"));

	CString sCmd, sKID, sKeyLen;
	sCmd = "80E61B";
	sKID = "02";
	sKeyLen = "80";
	sCmd += sKID;
	sCmd += sKeyLen;

	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("EXPORT RSA PUB KEY ERROR");
		ShowMessageString(sw);
		return;
	}

	ShowMessageString(_T("��ȡ RSA ��Կ�ɹ�"));
}

void CPublish_ToolDlg::SKF_EXPORT_SM2_PUB_KEY()
{
	ShowMessageString(_T("��ȡSM2��Կ"));

	CString sCmd, sKID;
	sCmd = "80E60B";
	sKID = "02";
	sCmd += sKID;
	sCmd += "40";

	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("EXPORT PSA PUB KEY ERROR");
		ShowMessageString(sw);
		return;
	}

	ShowMessageString(_T("��ȡ SM2 ��Կ�ɹ�"));
}


//TODO
void CPublish_ToolDlg::SKF_IMPORT_PUBKEY()
{
	ShowMessageString(_T("���빫Կ"));
	
	sw = SendCommandGetValueOrSW(SKF_IMPORT_PUBKEY_CMD, SKF_FLAG);
	if ((sw != "6670") && (sw != "6671") && (sw != "6672"))
		g_sSupportCmdList += "SKF_IMPORT_PUBKEY_CMD,  ";
}
void CPublish_ToolDlg::SKF_IMPORT_KEY()
{
	ShowMessageString(_T("������Կ"));
	
	sw = SendCommandGetValueOrSW(SKF_IMPORT_KEY_CMD, SKF_FLAG);
	if ((sw != "6670") && (sw != "6671") && (sw != "6672"))
		g_sSupportCmdList += "SKF_IMPORT_KEY_CMD,  ";
}
void CPublish_ToolDlg::SKF_DELET_KEY()
{
	ShowMessageString(_T("ɾ����Կ"));
	
	sw = SendCommandGetValueOrSW(SKF_DELET_KEY_CMD, SKF_FLAG);
	if ((sw != "6670") && (sw != "6671") && (sw != "6672"))
		g_sSupportCmdList += "SKF_DELET_KEY_CMD,  ";
}

void CPublish_ToolDlg::SKF_SESSION_KEY_ALG()
{
	ShowMessageString(_T("��������SM4 ��Կ"));

	CString sCmd, sSm4Key, sKeyLen;

	//set_sym_sm4_plain_key
	sCmd = SKF_SESSION_KEY_ALG_CMD;
	sSm4Key = "06060606060606060606060606060606";
	sKeyLen = "10";
	sCmd += sKeyLen;
	sCmd += sSm4Key;
	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("SET SM4 KEY ERROR");
		ShowMessageString(sw);
		return;
	}

	ShowMessageString(_T("��������SM4 ��Կ�ɹ�"));
}


void CPublish_ToolDlg::SKF_SET_MODE()
{
	ShowMessageString(_T("����SM4����ģʽ"));

	CString sCmd, sSm4Mode;

	sCmd = SKF_SET_MODE_CMD;
	sSm4Mode = "01"; //01:ECB 02:CBC 04:CFB 08:OFB 10:MAC
	sCmd += sSm4Mode;
	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("SET SM4 KEY ERROR");
		ShowMessageString(sw);
		return;
	}

	ShowMessageString(_T("����SM4����ģʽ�ɹ�"));
}

void CPublish_ToolDlg::SKF_SYM_MAC()
{
	ShowMessageString(_T("��Ϣ����������"));

	CString sCmd, sTnitVector, sRelVecLen, sPadTyp, sFeedBit, sSm4Key, sKeyLen, sSrcLen, sSrc;

	//set_sym_mac_mode
	//sCmd = "80D2001038";
	sCmd = "80D200102C";
	sTnitVector = "0001020304050607000102030405060700000000000000000000000000000000";
	/*sRelVecLen = "0000000000000010";
	sPadTyp = "0000000000000000";
	sFeedBit = "0000000000000000";*/
	sRelVecLen = "00000010";
	sPadTyp = "00000000";
	sFeedBit = "00000000";
	sCmd += sTnitVector;
	sCmd += sRelVecLen;
	sCmd += sPadTyp;
	sCmd += sFeedBit;
	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("SET MAC MODE ERROR");
		ShowMessageString(sw);
		return;
	}

	//set_sym_sm4_plain_key
	sCmd = "C0D00000";
	sSm4Key = "06060606060606060606060606060606";
	sKeyLen = "10";
	sCmd += sKeyLen;
	sCmd += sSm4Key;
	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("SET MAC KEY ERROR");
		ShowMessageString(sw);
		return;
	}

	//mac_update
	sCmd = "80D71000";
	sSrc = "0505050505050505050505050505050505050505050505050505050505050506";
	sSrcLen = "20";
	sCmd += sSrcLen;
	sCmd += sSrc;
	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("MAC UPDATE ERROR");
		ShowMessageString(sw);
		return;
	}

	//mac_final
	sCmd = "80D7000010";
	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("MAC FINAL ERROR");
		ShowMessageString(sw);
		return;
	}

	ShowMessageString(_T("��Ϣ����������ɹ�"));
}

void CPublish_ToolDlg::SKF_SYM_SET_KEY_RSA()
{
	ShowMessageString(_T("RSA ��������SM4 ��Կ"));

	CString sCmd, sTemp;
	CString sSM4Key = "09090909090909090909090909090909";
	BYTE aPlainData[16] = { 0 };
	BYTE aCipherData[128] = { 0 };
	BYTE aRsaKeyMod[256] = { 0 };
	BYTE aRsaPubExp[4] = { 0x00, 0x01, 0x00, 0x01 };
	CstringToByte(sSM4Key, aPlainData);

	SKF_GENARATE_RSA_KEY_PAIR();

	//��ȡRSA��Կ
	
	sw = SendCommandGetValueOrSW("80E61B0280", SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("EXPORT RSA PUB KEY ERROR");
		ShowMessageString(sw);
		return;
	}
	CstringToByte(sValue, &aRsaKeyMod[128]);

	rsa_pub_pkcs1_encrypt2(aRsaKeyMod, aRsaPubExp, aPlainData, aCipherData, 16);
	sCmd = "C0 D0 00 01 81 02";
	for (int i = 0; i< 128; i++)
	{
		sTemp.Format("%02x", aCipherData[i]);
		sCmd += sTemp;
	}
	sCmd.MakeUpper();

	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("SYM SET KEY RSA ERROR");
		ShowMessageString(sw);
		return;
	}

	ShowMessageString(_T("RSA ��������SM4 ��Կ�ɹ�"));
}

//TODO
void CPublish_ToolDlg::SKF_SYM_ENCRYPT()
{
	ShowMessageString(_T("�ԳƼ���"));
	
	sw = SendCommandGetValueOrSW(SKF_SYM_ENCRYPT_CMD, SKF_FLAG);
	if ((sw != "6670") && (sw != "6671") && (sw != "6672"))
		g_sSupportCmdList += "SKF_SYM_ENCRYPT_CMD,  ";
}
void CPublish_ToolDlg::SKF_SYM_DECRYPT()
{
	ShowMessageString(_T("�Գƽ���"));
	
	sw = SendCommandGetValueOrSW(SKF_SYM_DECRYPT_CMD, SKF_FLAG);
	if ((sw != "6670") && (sw != "6671") && (sw != "6672"))
		g_sSupportCmdList += "SKF_SYM_DECRYPT_CMD,  ";
}

void CPublish_ToolDlg::SKF_HASH_SM3()
{
	ShowMessageString(_T("�����ϣֵ"));

	CString sHashData, sDataLen, sCmd;

	sHashData = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
	sDataLen = "20";

	//��ȫ��������---����HASH
	
	sw = SendCommandGetValueOrSW("002201AA03870142", SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("Manage Secur Env ERROR");
		ShowMessageString(sw);
		return;
	}

	//hash_sm3_update
	sCmd = "102A9080";
	sCmd += sDataLen;
	sCmd += sHashData;
	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("HAHS UPDATE ERROR");
		ShowMessageString(sw);
		return;
	}

	//hash_sm3_final
	sCmd = "002A908020";
	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("HASH FINAL ERROR");
		ShowMessageString(sw);
		return;
	}
	g_sHashValue = sValue;

	ShowMessageString(_T("�����ϣֵ�ɹ�"));
}

void CPublish_ToolDlg::SKF_SM2_SIGN()
{
	ShowMessageString(_T("SM2ǩ��"));

	CString sCmd;

	//SKF_HASH_SM3();

	//��ȫ��������----sm2ǩ��
	
	sw = SendCommandGetValueOrSW("002241B6078001428402020A", SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("Manage Secur Env ERROR");
		ShowMessageString(sw);
		return;
	}

	//����ϣֵ����Ӳ����
	sCmd = "002A908120";
	sCmd += g_sHashValue;
	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("PUT HASH ERROR");
		ShowMessageString(sw);
		return;
	}

	//SM2ǩ��
	sCmd = "002A9E0040";
	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("SM2 SIGN ERROR");
		ShowMessageString(sw);
		return;
	}

	g_sSignValue = sValue;

	ShowMessageString(_T("SM2ǩ���ɹ�"));
}

void CPublish_ToolDlg::SKF_SM2_VERTFY()
{
	ShowMessageString(_T("SM2��ǩ"));

	CString sCmd;

	//��ȫ��������----sm2��ǩ
	
	sw = SendCommandGetValueOrSW("002281B6078001428302020B", SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("Manage Secur Env ERROR");
		ShowMessageString(sw);
		return;
	}

	//����ϣֵ����Ӳ����
	sCmd = "002A908120";
	sCmd += g_sHashValue;
	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("PUT HASH ERROR");
		ShowMessageString(sw);
		return;
	}

	//SM2��ǩ
	sCmd = "002A00A840";
	sCmd += g_sSignValue;
	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("SM2 VERTFY ERROR");
		ShowMessageString(sw);
		return;
	}

	ShowMessageString(_T("SM2��ǩ�ɹ�"));
}





//test case
//��MF��ȡ�豸��Ϣ
void CPublish_ToolDlg::SKF_Functional_Testing_Case_1()
{
	SKF_GET_DEV_INFO();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "1, ";
		return;
	}

	g_ulTestRightCnt++;
}

//����������֤���ݽ����豸��֤
void CPublish_ToolDlg::SKF_Functional_Testing_Case_2()
{
	SKF_DEVICE_AUTH();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "2, ";
		return;
	}

	g_ulTestRightCnt++;
}

//����������֤���ݽ����豸��֤��Ӧ����6989
void CPublish_ToolDlg::SKF_Functional_Testing_Case_3()
{
	BYTE asDevAuthKey[16] = { 0x32, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
	BYTE asTemp[16] = { 0 };

	memcpy(asTemp, g_aCurDevAuthKey, 16);
	memcpy(g_aCurDevAuthKey, asDevAuthKey, 16);

	SKF_DEVICE_AUTH();
	memcpy(g_aCurDevAuthKey, asTemp, 16);
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "3, ";
		return;
	}

	g_ulTestRightCnt++;
}

//�������֤���ݳ��ȣ�Ӧ����6700
void CPublish_ToolDlg::SKF_Functional_Testing_Case_4()
{
	g_ulTestRightCnt++;
}

//�޸��豸��ǩ���ȡ�豸��Ϣ���鿴�µı�ǩֵ�Ƿ�Ϊ�趨ֵ
void CPublish_ToolDlg::SKF_Functional_Testing_Case_5()
{
	BYTE asLable[] = { "aaaaaaaa" };
	BYTE asTemp[32] = { 0 };

	SKF_SET_DEV_INFO();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "5, ";
		return;
	}

	SKF_GET_DEV_INFO();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "5, ";
		return;
	}

	/*CstringToByte(sValue, asTemp);
	if (memcmp(asLable, asTemp, sizeof(asLable)) != 0)
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "5, ";
		return;
	}*/

	g_ulTestRightCnt++;
}

//�޸��豸��ǩ,��ǩ����32�ֽڣ�Ӧ����6985
void CPublish_ToolDlg::SKF_Functional_Testing_Case_6()
{
	CString sLable = "84EC010022";
	CString sTemp;
	BYTE asLable[34] = { 0 };

	memset(asLable, 'a', 34);

	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);
	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);

	for (int i = 0; i< 34; i++)
	{
		sTemp.Format("%02x", asLable[i]);
		sLable += sTemp;
	}
	sLable.MakeUpper();

	
	sw = SendCommandGetValueOrSW(sLable, SKF_FLAG);
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "6, ";
		return;
	}

	g_ulTestRightCnt++;
}


void CPublish_ToolDlg::SKF_Functional_Testing_Case_7()
{
	g_ulTestRightCnt++;
}

//���Ӧ�õİ�ȫ״̬���޷������ļ�
void CPublish_ToolDlg::SKF_Functional_Testing_Case_8()
{
	SKF_DEVICE_AUTH();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "8, ";
		return;
	}

	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "8, ";
		return;
	}

	SKF_SELECT_DF0();
	SKF_VERIFY_PIN();
	SKF_CREATE_EF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "8, ";
		return;
	}

	SKF_SELECT_DF0();
	
	sw = SendCommandGetValueOrSW("84EC03000100", SKF_FLAG);
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "8, ";
		return;
	}

	SKF_CREATE_EF1();
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "8, ";
		return;
	}

	g_ulTestRightCnt++;
}

//�޸��豸��֤��ԿΪ32333435363738393233343536373839������Կ�����豸��֤
void CPublish_ToolDlg::SKF_Functional_Testing_Case_9()
{
	BYTE asTemp[16] = { 0 };
	memcpy(asTemp, g_aCurDevAuthKey, 16);
	
	SKF_SELECT_MF();

	SKF_DEVICE_AUTH();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "9, ";
		return;
	}

	SKF_MODIFY_DEV_AUTH_KEY();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "9, ";
		return;
	}

	SKF_DEVICE_AUTH();
	memcpy(g_aCurDevAuthKey, asTemp, 16);
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "9, ";
		return;
	}

	g_ulTestRightCnt++;
	SKF_DELET_FILE();
	SKF_CREATE_MF();
}

//�޸��豸��֤��ԿΪ31323334353637383132333435363738���þ�Կ32333435363738393233343536373839�����豸��֤��Ӧ����6989
void CPublish_ToolDlg::SKF_Functional_Testing_Case_10()
{
	BYTE asDevAuthKey[16] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
	BYTE asTemp[16] = { 0 };

	SKF_SELECT_MF();

	SKF_DEVICE_AUTH();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "10, ";
		return;
	}

	SKF_MODIFY_DEV_AUTH_KEY();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "10, ";
		return;
	}

	memcpy(g_aCurDevAuthKey, asDevAuthKey, 16);

	SKF_DEVICE_AUTH();
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "10, ";
		return;
	}

	g_ulTestRightCnt++;
}

//�޸��豸��֤��Կǰ�������豸��֤��Ӧ����6982
void CPublish_ToolDlg::SKF_Functional_Testing_Case_11()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();

	SKF_MODIFY_DEV_AUTH_KEY();
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "11, ";
		return;
	}

	g_ulTestRightCnt++;
}

//��ȡ8λ�����
void CPublish_ToolDlg::SKF_Functional_Testing_Case_12()
{
	SKF_GET_RAND();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "12, ";
		return;
	}

	g_ulTestRightCnt++;
}

//������ȡ���������
void CPublish_ToolDlg::SKF_Functional_Testing_Case_13()
{
	SKF_GET_RAND();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "13, ";
		return;
	}

	SKF_GET_RAND();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "13, ";
		return;
	}

	g_ulTestRightCnt++;

}

//������ȡ�������������ȡ������������豸��֤
void CPublish_ToolDlg::SKF_Functional_Testing_Case_14()
{
	SKF_GET_RAND();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "14, ";
		return;
	}

	SKF_DEVICE_AUTH();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "14, ";
		return;
	}

	g_ulTestRightCnt++;
}

// ������ȡ��������õ�һ�λ�ȡ������������豸��֤
void CPublish_ToolDlg::SKF_Functional_Testing_Case_15()
{
	g_ulTestRightCnt++;
}

//����1024b rsa pub key����������Կ
void CPublish_ToolDlg::SKF_Functional_Testing_Case_16()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	SKF_SELECT_DF0();
	SKF_VERIFY_PIN();

	SKF_GENARATE_RSA_KEY_PAIR();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "16, ";
		return;
	}

	SKF_EXPORT_PSA_PUB_KEY();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "16, ";
		return;
	}

	g_ulTestRightCnt++;
}

//����512b rsa pub key
void CPublish_ToolDlg::SKF_Functional_Testing_Case_17()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	SKF_VERIFY_PIN();

	//��ȫ��������������rsa��Կ��
	
	sw = SendCommandGetValueOrSW("002201B80483000200", SKF_FLAG);
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "17, ";
		return;
	}

	
	sw = SendCommandGetValueOrSW("0046000002020040", SKF_FLAG);
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "17, ";
		return;
	}

	g_ulTestRightCnt++;
}

//����256b rsa pub key ����6A80
void CPublish_ToolDlg::SKF_Functional_Testing_Case_18()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	SKF_VERIFY_PIN();

	//��ȫ��������������rsa��Կ��
	
	sw = SendCommandGetValueOrSW("002201B80483000200", SKF_FLAG);
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "18, ";
		return;
	}

	
	sw = SendCommandGetValueOrSW("00460000020100", SKF_FLAG);
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "18, ";
		return;
	}

	g_ulTestRightCnt++;
}

//����ģ��Ϊ64B��SM2��Կ�ԣ���������Կ
void CPublish_ToolDlg::SKF_Functional_Testing_Case_19()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	SKF_VERIFY_PIN();

	SKF_GENARATE_SM2_KEY_PAIR();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "19, ";
		return;
	}

	SKF_EXPORT_SM2_PUB_KEY();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "19, ";
		return;
	}

	g_ulTestRightCnt++;
}

//���㵥���ϣֵ
void CPublish_ToolDlg::SKF_Functional_Testing_Case_20()
{
	SKF_HASH_SM3();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "20, ";
		return;
	}
	g_ulTestRightCnt++;
}

//�����ϣֵ������ϣֵ����Ӳ���У�����SM2��Կ������SM2ǩ��
void CPublish_ToolDlg::SKF_Functional_Testing_Case_21()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	SKF_VERIFY_PIN();

	SKF_HASH_SM3();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "21, ";
		return;
	}

	SKF_GENARATE_SM2_KEY_PAIR();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "21, ";
		return;
	}

	SKF_SM2_SIGN();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "21, ";
		return;
	}

	g_ulTestRightCnt++;
}

//�����ϣֵ������ϣֵ����Ӳ���У�����SM2��Կ������SM2ǩ��������SM2��ǩ
void CPublish_ToolDlg::SKF_Functional_Testing_Case_22()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	SKF_VERIFY_PIN();

	SKF_HASH_SM3();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "22, ";
		return;
	}

	SKF_GENARATE_SM2_KEY_PAIR();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "22, ";
		return;
	}

	SKF_SM2_SIGN();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "22, ";
		return;
	}

	SKF_SM2_VERTFY();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "22, ";
		return;
	}

	g_ulTestRightCnt++;
}

//����SM4��Կ����ʽΪRSA ���ģ�
void CPublish_ToolDlg::SKF_Functional_Testing_Case_23()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	SKF_VERIFY_PIN();

	SKF_SYM_SET_KEY_RSA();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "23, ";
		return;
	}

	g_ulTestRightCnt++;
}

//����SM4��Կ����ʽΪSM2���ģ�
void CPublish_ToolDlg::SKF_Functional_Testing_Case_24()
{
	g_ulTestRightCnt++;
}

//��������(32B)��Ϣ����������
void CPublish_ToolDlg::SKF_Functional_Testing_Case_25()
{
	SKF_SYM_MAC();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "25, ";
		return;
	}

	g_ulTestRightCnt++;
}

//����(32B)������Ϣ����������
void CPublish_ToolDlg::SKF_Functional_Testing_Case_26()
{
	g_ulTestRightCnt++;
}

//û���豸��֤�ʹ����ļ�
void CPublish_ToolDlg::SKF_Functional_Testing_Case_27()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();
	
	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);

	
	sw = SendCommandGetValueOrSW(SKF_CREATE_FILE_DF1_CMD, SKF_FLAG);
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "27, ";
		return;
	}

	g_ulTestRightCnt++;
}

//�豸��֤�ɹ��󴴽��ļ�
void CPublish_ToolDlg::SKF_Functional_Testing_Case_28()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF(); 
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "28, ";
		return;
	}

	g_ulTestRightCnt++;
}

//����ͬ��Ӧ��
void CPublish_ToolDlg::SKF_Functional_Testing_Case_29()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "29, ";
		return;
	}

	SKF_CREATE_DF0();
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "29, ";
		return;
	}

	g_ulTestRightCnt++;
}

//1���豸��֤ 2������Ӧ�� 2��ɾ��Ӧ��
void CPublish_ToolDlg::SKF_Functional_Testing_Case_30()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "30, ";
		return;
	}

	SKF_DELET_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "30, ";
		return;
	}

	g_ulTestRightCnt++;
}

//ɾ���������ļ�
void CPublish_ToolDlg::SKF_Functional_Testing_Case_31()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_DELET_DF0();
	/*if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "31, ";
		return;
	}*/

	g_ulTestRightCnt++;
}

//ö��Ӧ��
void CPublish_ToolDlg::SKF_Functional_Testing_Case_32()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "32, ";
		return;
	}

	SKF_GET_DF_LIST();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "32, ";
		return;
	}

	g_ulTestRightCnt++;
}

//û��PINУ��ʹ����ļ� 
void CPublish_ToolDlg::SKF_Functional_Testing_Case_33()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "33, ";
		return;
	}

	SKF_CREATE_EF0();
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "33, ";
		return;
	}

	g_ulTestRightCnt++;
}

//���������ļ�
void CPublish_ToolDlg::SKF_Functional_Testing_Case_34()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "34, ";
		return;
	}

	SKF_VERIFY_PIN();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "34, ";
		return;
	}

	SKF_CREATE_EF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "34, ";
		return;
	}

	g_ulTestRightCnt++;
}

// ����ͬ���ļ�
void CPublish_ToolDlg::SKF_Functional_Testing_Case_35()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "35, ";
		return;
	}

	SKF_VERIFY_PIN();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "35, ";
		return;
	}

	SKF_CREATE_EF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "35, ";
		return;
	}

	SKF_CREATE_EF0();
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "35, ";
		return;
	}

	g_ulTestRightCnt++;
}

//ö���ļ�
void CPublish_ToolDlg::SKF_Functional_Testing_Case_36()
{
	SKF_DELET_FILE();
	SKF_CREATE_FILE();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "36, ";
		return;
	}

	SKF_SELECT_DF0();
	SKF_VERIFY_PIN();

	SKF_GET_EF_LIST();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "36, ";
		return;
	}

	g_ulTestRightCnt++;
}

//ɾ���ļ�ʱû���Ӧ�ð�ȫ״̬�����ļ�
void CPublish_ToolDlg::SKF_Functional_Testing_Case_37()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "37, ";
		return;
	}

	SKF_VERIFY_PIN();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "37, ";
		return;
	}

	SKF_CREATE_EF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "37, ";
		return;
	}

	SKF_SELECT_MF();
	SKF_DELET_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "37, ";
		return;
	}

	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "37, ";
		return;
	}

	SKF_CREATE_EF0();
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "37, ";
		return;
	}

	g_ulTestRightCnt++;
}

//��ȡ�ļ���Ϣ
void CPublish_ToolDlg::SKF_Functional_Testing_Case_38()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "38, ";
		return;
	}

	SKF_VERIFY_PIN();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "38, ";
		return;
	}

	SKF_CREATE_EF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "38, ";
		return;
	}

	SKF_SELECT_EF0();
	SKF_GET_FILE_INFO();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "38, ";
		return;
	}

	g_ulTestRightCnt++;
}

//д���ļ����ٶ�ȡ�ļ����Ƚ���������
void CPublish_ToolDlg::SKF_Functional_Testing_Case_39()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "39, ";
		return;
	}

	SKF_VERIFY_PIN();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "39, ";
		return;
	}

	SKF_CREATE_EF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "39, ";
		return;
	}

	SKF_SELECT_EF0();
	SKF_WRITE_FILE();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "39, ";
		return;
	}

	SKF_READ_FILE();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "39, ";
		return;
	}

	g_ulTestRightCnt++; 
}

//д���ļ����Ͽ��豸�������Ӻ��ٶ�ȡ�ļ����ݣ��Ƚ���������
void CPublish_ToolDlg::SKF_Functional_Testing_Case_40()
{
	g_ulTestRightCnt++;
}

//�ļ�д��ƫ���������ļ���С
void CPublish_ToolDlg::SKF_Functional_Testing_Case_41()
{
	CString sCmd;

	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "41, ";
		return;
	}

	SKF_VERIFY_PIN();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "41, ";
		return;
	}

	SKF_CREATE_EF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "41, ";
		return;
	}

	sCmd = "00D60100082122232425262728";
	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "41, ";
		return;
	}

	g_ulTestRightCnt++;
}

//�ļ�д�����ݳ����ļ���С
void CPublish_ToolDlg::SKF_Functional_Testing_Case_42()
{
	CString sCmd;

	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "42, ";
		return;
	}

	SKF_VERIFY_PIN();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "42, ";
		return;
	}

	SKF_CREATE_EF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "42, ";
		return;
	}

	sCmd = "00D600001021222324252627283132333435363738";
	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "42, ";
		return;
	}

	g_ulTestRightCnt++;
}

//���ļ�ƫ���������ļ���С
void CPublish_ToolDlg::SKF_Functional_Testing_Case_43()
{
	CString sCmd;

	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "43, ";
		return;
	}

	SKF_VERIFY_PIN();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "43, ";
		return;
	}

	SKF_CREATE_EF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "43, ";
		return;
	}

	sCmd = "00B0001008";
	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "43, ";
		return;
	}

	g_ulTestRightCnt++;
}

//���ļ�ƫ���������ļ���С
void CPublish_ToolDlg::SKF_Functional_Testing_Case_44()
{
	CString sCmd;

	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "44, ";
		return;
	}

	SKF_VERIFY_PIN();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "44, ";
		return;
	}

	SKF_CREATE_EF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "44, ";
		return;
	}

	//���ļ�ƫ���������ļ���С�᷵���ļ�ʣ�µ����ݣ����᷵��
	/*sCmd = "00B000020F";
	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "44, ";
		return;
	}*/

	g_ulTestRightCnt++;
}

//����Ӧ��Ȼ��ɾ������������10��
void CPublish_ToolDlg::SKF_Functional_Testing_Case_45()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();

	for (int i = 0; i < 10; i++)
	{
		SKF_CREATE_DF0();
		if (sw != "9000")
		{
			g_ulTestErrCnt++;
			g_sTestErrList += "45, ";
			return;
		}
		SKF_SELECT_MF();
		SKF_DELET_DF0();
		if (sw != "9000")
		{
			g_ulTestErrCnt++;
			g_sTestErrList += "45, ";
			return;
		}
	}

	g_ulTestRightCnt++;
}

//�������豸��ֱ֤��ö��Ӧ��
void CPublish_ToolDlg::SKF_Functional_Testing_Case_46()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "46, ";
		return;
	}

	SKF_GET_DF_LIST();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "46, ";
		return;
	}

	g_ulTestRightCnt++;
}

//Ŀǰ��֧�ִ���3��Ӧ�ã�������4��Ӧ��Ӧ���޷������ɹ�
void CPublish_ToolDlg::SKF_Functional_Testing_Case_47()
{
	g_ulTestRightCnt++;
}

//Ӧ�ô�������������򿪣�ɾ�����ʧ��
void CPublish_ToolDlg::SKF_Functional_Testing_Case_48()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "48, ";
		return;
	}

	SKF_SELECT_MF();
	/*if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "48, ";
		return;
	}*/

	SKF_DELET_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "48, ";
		return;
	}

	SKF_SELECT_DF0();
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "48, ";
		return;
	}

	g_ulTestRightCnt++;
}

//������ѡ��Ӧ�ã���ȡӦ����Ϣ
void CPublish_ToolDlg::SKF_Functional_Testing_Case_49()
{
	g_ulTestRightCnt++;
}

//У���û�PIN
void CPublish_ToolDlg::SKF_Functional_Testing_Case_50()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "50, ";
		return;
	}

	SKF_VERIFY_PIN();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "50, ";
		return;
	}

	g_ulTestRightCnt++;
}

//У�����ԱPIN
void CPublish_ToolDlg::SKF_Functional_Testing_Case_51()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "51, ";
		return;
	}

	SKF_VERIFY_SOPIN();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "51, ";
		return;
	}

	g_ulTestRightCnt++;

	
}

// ��������û�PIN��͹���ԱPIN��
void CPublish_ToolDlg::SKF_Functional_Testing_Case_52()
{
	CString sTemp;
	CString sSopin = "0701020304050607000102030405060700010203040506070001020304050607";

	sTemp = sVerPinHash;

	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "52, ";
		return;
	}

	sVerPinHash = sSopin;
	SKF_VERIFY_PIN();
	sVerPinHash = sTemp;
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "52, ";
		return;
	}

	g_ulTestRightCnt++;
}

// �ȴ������PIN�룬У�������ʣ�������������ȷPIN��У�飬У��ɹ���ʣ�����Դ����ûس�ֵ
void CPublish_ToolDlg::SKF_Functional_Testing_Case_53()
{
	CString sTemp;
	CString sSopin = "0701020304050607000102030405060700010203040506070001020304050607";

	sTemp = sVerPinHash;

	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "53, ";
		return;
	}

	sVerPinHash = sSopin;
	SKF_VERIFY_PIN();
	sVerPinHash = sTemp;
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "53, ";
		return;
	}

	SKF_VERIFY_PIN();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "53, ";
		return;
	}

	g_ulTestRightCnt++;
}

// �޸��û�PIN, ������PIN����У��
void CPublish_ToolDlg::SKF_Functional_Testing_Case_54()
{
	CString sPinHash = "0807060504030201080706050403020108070605040302010807060504030201";

	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "54, ";
		return;
	}

	SKF_MODIFY_PIN();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "54, ";
		return;
	}

	SKF_VERIFY_PIN();
	sVerPinHash = sPinHash;
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "54, ";
		return;
	}

	g_ulTestRightCnt++;
}

// �޸Ĺ���ԱPIN, ������PIN����У��
void CPublish_ToolDlg::SKF_Functional_Testing_Case_55()
{
	CString sPinHash, sCmd, sTemp;
	BYTE asRandData[8] = { 0 };
	BYTE asOldPinHash[32] = { 0 };
	BYTE asNewPinHash[32] = { 0 };
	BYTE aPlainData[64] = { 0 };
	BYTE aCipherData[128] = { 0 };
	BYTE aRsaKeyMod[256] = { 0 };
	BYTE aRsaPubExp[4] = { 0x00, 0x01, 0x00, 0x01 };

	sPinHash = "0001020304050607000102030405060700010203040506070001020304050607";
	CstringToByte(sPinHash, asOldPinHash);
	sPinHash = "0102030405060708010203040506070801020304050607080102030405060708";
	CstringToByte(sPinHash, asNewPinHash);

	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "55, ";
		return;
	}

	//��ȡ�����
	
	sw = SendCommandGetValueOrSW(SKF_GET_RAND_CMD, SKF_FLAG);
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "55, ";
		return;
	}
	CstringToByte(sValue, asRandData);

	for (int i = 0; i < 32; i++) aPlainData[i] = asOldPinHash[i] ^ asNewPinHash[i];

	memcpy(&aPlainData[32], asNewPinHash, 32);

	for (int i = 0; i < 64; i++) aPlainData[i] ^= asRandData[i % 8];

	SKF_SELECT_DF0();

	//��ȡRSA��Կ
	
	sw = SendCommandGetValueOrSW(SKF_GET_RSA_PUB_KEY_CMD, SKF_FLAG);
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "55, ";
		return;
	}
	CstringToByte(sValue, &aRsaKeyMod[128]);

	rsa_pub_pkcs1_encrypt(aRsaKeyMod, aRsaPubExp, aPlainData, aCipherData, 64);
	sCmd = "0024000080";
	for (int i = 0; i< 128; i++)
	{
		sTemp.Format("%02x", aCipherData[i]);
		sCmd += sTemp;
	}
	sCmd.MakeUpper();

	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "55, ";
		return;
	}

	sVerSoPinHash = sPinHash;
	SKF_VERIFY_SOPIN();
	sVerSoPinHash = "0001020304050607000102030405060700010203040506070001020304050607";
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "55, ";
		return;
	}

	g_ulTestRightCnt++;
}

// �޸��û�PIN���þ�PIN����У��
void CPublish_ToolDlg::SKF_Functional_Testing_Case_56()
{
	CString sPinHash = "0807060504030201080706050403020108070605040302010807060504030201";

	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "56, ";
		return;
	}

	SKF_MODIFY_PIN();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "56, ";
		return;
	}

	sVerPinHash = sPinHash;

	SKF_VERIFY_PIN();
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "56, ";
		return;
	}

	g_ulTestRightCnt++;
}

// �޸��û�PINʱ����ľ�PIN����
void CPublish_ToolDlg::SKF_Functional_Testing_Case_57()
{
	CString sPinHash, sCmd, sTemp;
	BYTE asRandData[8] = { 0 };
	BYTE asOldPinHash[32] = { 0 };
	BYTE asNewPinHash[32] = { 0 };
	BYTE aPlainData[64] = { 0 };
	BYTE aCipherData[128] = { 0 };
	BYTE aRsaKeyMod[256] = { 0 };
	BYTE aRsaPubExp[4] = { 0x00, 0x01, 0x00, 0x01 };

	sPinHash = "0107060504030201080706050403020108070605040302010807060504030201";
	CstringToByte(sPinHash, asOldPinHash);
	sPinHash = "0405060700010203040506070001020304050607000102030405060700010203";
	CstringToByte(sPinHash, asNewPinHash);

	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "57, ";
		return;
	}

	//��ȡ�����
	
	sw = SendCommandGetValueOrSW(SKF_GET_RAND_CMD, SKF_FLAG);
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "57, ";
		return;
	}
	CstringToByte(sValue, asRandData);

	for (int i = 0; i < 32; i++) aPlainData[i] = asOldPinHash[i] ^ asNewPinHash[i];

	memcpy(&aPlainData[32], asNewPinHash, 32);

	for (int i = 0; i < 64; i++) aPlainData[i] ^= asRandData[i % 8];

	//��ȡRSA��Կ
	
	sw = SendCommandGetValueOrSW(SKF_GET_RSA_PUB_KEY_CMD, SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("EXPORT RSA PUB KEY ERROR");
		ShowMessageString(sw);
		return;
	}
	CstringToByte(sValue, &aRsaKeyMod[128]);

	rsa_pub_pkcs1_encrypt(aRsaKeyMod, aRsaPubExp, aPlainData, aCipherData, 64);
	sCmd = SKF_MODIFY_PIN_CMD;
	for (int i = 0; i< 128; i++)
	{
		sTemp.Format("%02x", aCipherData[i]);
		sCmd += sTemp;
	}
	sCmd.MakeUpper();

	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "57, ";
		return;
	}

	g_ulTestRightCnt++;
}

// �޸Ĺ���ԱPIN���þ�PIN����У��
void CPublish_ToolDlg::SKF_Functional_Testing_Case_58()
{
	CString sPinHash, sCmd, sTemp;
	BYTE asRandData[8] = { 0 };
	BYTE asOldPinHash[32] = { 0 };
	BYTE asNewPinHash[32] = { 0 };
	BYTE aPlainData[64] = { 0 };
	BYTE aCipherData[128] = { 0 };
	BYTE aRsaKeyMod[256] = { 0 };
	BYTE aRsaPubExp[4] = { 0x00, 0x01, 0x00, 0x01 };

	sPinHash = "0001020304050607000102030405060700010203040506070001020304050607";
	CstringToByte(sPinHash, asOldPinHash);
	sPinHash = "0102030405060708010203040506070801020304050607080102030405060708";
	CstringToByte(sPinHash, asNewPinHash);

	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "58, ";
		return;
	}

	//��ȡ�����
	
	sw = SendCommandGetValueOrSW(SKF_GET_RAND_CMD, SKF_FLAG);
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "58, ";
		return;
	}
	CstringToByte(sValue, asRandData);

	for (int i = 0; i < 32; i++) aPlainData[i] = asOldPinHash[i] ^ asNewPinHash[i];

	memcpy(&aPlainData[32], asNewPinHash, 32);

	for (int i = 0; i < 64; i++) aPlainData[i] ^= asRandData[i % 8];

	SKF_SELECT_DF0();

	//��ȡRSA��Կ
	
	sw = SendCommandGetValueOrSW(SKF_GET_RSA_PUB_KEY_CMD, SKF_FLAG);
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "58, ";
		return;
	}
	CstringToByte(sValue, &aRsaKeyMod[128]);

	rsa_pub_pkcs1_encrypt(aRsaKeyMod, aRsaPubExp, aPlainData, aCipherData, 64);
	sCmd = "0024000080";
	for (int i = 0; i< 128; i++)
	{
		sTemp.Format("%02x", aCipherData[i]);
		sCmd += sTemp;
	}
	sCmd.MakeUpper();

	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "58, ";
		return;
	}

	sVerSoPinHash = "0001020304050607000102030405060700010203040506070001020304050607";
	SKF_VERIFY_SOPIN();
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "58, ";
		return;
	}

	g_ulTestRightCnt++;
}

// �޸Ĺ���ԱPINʱ����ľ�PIN����
void CPublish_ToolDlg::SKF_Functional_Testing_Case_59()
{
	CString sPinHash, sCmd, sTemp;
	BYTE asRandData[8] = { 0 };
	BYTE asOldPinHash[32] = { 0 };
	BYTE asNewPinHash[32] = { 0 };
	BYTE aPlainData[64] = { 0 };
	BYTE aCipherData[128] = { 0 };
	BYTE aRsaKeyMod[256] = { 0 };
	BYTE aRsaPubExp[4] = { 0x00, 0x01, 0x00, 0x01 };

	sPinHash = "0101020304050607000102030405060700010203040506070001020304050607";
	CstringToByte(sPinHash, asOldPinHash);
	sPinHash = "0102030405060708010203040506070801020304050607080102030405060708";
	CstringToByte(sPinHash, asNewPinHash);

	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "59, ";
		return;
	}

	//��ȡ�����
	
	sw = SendCommandGetValueOrSW(SKF_GET_RAND_CMD, SKF_FLAG);
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "59, ";
		return;
	}
	CstringToByte(sValue, asRandData);

	for (int i = 0; i < 32; i++) aPlainData[i] = asOldPinHash[i] ^ asNewPinHash[i];

	memcpy(&aPlainData[32], asNewPinHash, 32);

	for (int i = 0; i < 64; i++) aPlainData[i] ^= asRandData[i % 8];
	
	SKF_SELECT_DF0();

	//��ȡRSA��Կ
	
	sw = SendCommandGetValueOrSW(SKF_GET_RSA_PUB_KEY_CMD, SKF_FLAG);
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "59, ";
		return;
	}
	CstringToByte(sValue, &aRsaKeyMod[128]);

	rsa_pub_pkcs1_encrypt(aRsaKeyMod, aRsaPubExp, aPlainData, aCipherData, 64);
	sCmd = "0024000080";
	for (int i = 0; i< 128; i++)
	{
		sTemp.Format("%02x", aCipherData[i]);
		sCmd += sTemp;
	}
	sCmd.MakeUpper();

	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "59, ";
		return;
	}

	g_ulTestRightCnt++;
}

//  �û�PIN������������ȷPINУ��
void CPublish_ToolDlg::SKF_Functional_Testing_Case_60()
{
	CString sPinHash = "0807060504030201080706050403020108070605040302010807060504030201";
	CString sErrPinHash = "0807060504030201080706050403020108070605040302010807060504030202";

	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "60, ";
		return;
	}

	sVerPinHash = sErrPinHash;
	for (int i = 0; i < 6; i++)
	{
		SKF_VERIFY_PIN();
		if (sw == "9000")
		{
			g_ulTestErrCnt++;
			g_sTestErrList += "60, ";
			return;
		}
	}

	sVerPinHash = sPinHash;
	SKF_VERIFY_PIN();
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "60, ";
		return;
	}

	g_ulTestRightCnt++;
}

// ����ԱPIN������������ȷPIN  У��
void CPublish_ToolDlg::SKF_Functional_Testing_Case_61()
{
	CString sPinHash = "0001020304050607000102030405060700010203040506070001020304050607";
	CString sErrPinHash = "0807060504030201080706050403020108070605040302010807060504030202";

	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "61, ";
		return;
	}

	sVerSoPinHash = sErrPinHash;
	for (int i = 0; i < 6; i++)
	{
		SKF_VERIFY_SOPIN();
		if (sw == "9000")
		{
			g_ulTestErrCnt++;
			g_sTestErrList += "61, ";
			return;
		}
	}

	sVerSoPinHash = sPinHash;
	SKF_VERIFY_SOPIN();
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "61, ";
		return;
	}

	g_ulTestRightCnt++;
}

// �û�PIN ������������ȷPIN �޸�PIN
void CPublish_ToolDlg::SKF_Functional_Testing_Case_62()
{
	CString sPinHash = "0807060504030201080706050403020108070605040302010807060504030201";
	CString sErrPinHash = "0807060504030201080706050403020108070605040302010807060504030202";

	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "62, ";
		return;
	}

	sVerPinHash = sErrPinHash;
	for (int i = 0; i < 6; i++)
	{
		SKF_VERIFY_PIN();
		if (sw == "9000")
		{
			g_ulTestErrCnt++;
			g_sTestErrList += "62, ";
			return;
		}
	}

	sVerPinHash = sPinHash;
	SKF_MODIFY_PIN();
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "62, ";
		return;
	}

	g_ulTestRightCnt++;
}

// ����ԱPIN������������ȷPIN�޸�PIN
void CPublish_ToolDlg::SKF_Functional_Testing_Case_63()
{
	g_ulTestRightCnt++;
}

// PIN�������󣬽��н�������������PIN����У��
void CPublish_ToolDlg::SKF_Functional_Testing_Case_64()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "64, ";
		return;
	}

	SKF_UNLOCK_RESET_PIN();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "64, ";
		return;
	}

	SKF_VERIFY_PIN();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "64, ";
		return;
	}

	g_ulTestRightCnt++;
}

// PIN�������󣬽��н���������������PIN�����޸�PIN
void CPublish_ToolDlg::SKF_Functional_Testing_Case_65()
{
	CString sPinHash = "0807060504030201080706050403020108070605040302010807060504030201";

	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "65, ";
		return;
	}

	SKF_UNLOCK_RESET_PIN();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "65, ";
		return;
	}

	SKF_MODIFY_PIN();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "65, ";
		return;
	}

	sVerPinHash = sPinHash;
	g_ulTestRightCnt++;
}

//����Ĺ���ԱPIN����PIN
void CPublish_ToolDlg::SKF_Functional_Testing_Case_66()
{
	g_ulTestRightCnt++;
}

//�����û�PIN ǰ����ԱPIN ������
void CPublish_ToolDlg::SKF_Functional_Testing_Case_67()
{
	CString sPinHash = "0001020304050607000102030405060700010203040506070001020304050607";
	CString sErrPinHash = "0807060504030201080706050403020108070605040302010807060504030202";

	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "67, ";
		return;
	}

	sVerSoPinHash = sErrPinHash;
	for (int i = 0; i < 6; i++)
	{
		SKF_VERIFY_SOPIN();
		if (sw == "9000")
		{
			g_ulTestErrCnt++;
			g_sTestErrList += "67, ";
			return;
		}
	}

	sVerSoPinHash = sPinHash;

	SKF_UNLOCK_RESET_PIN();
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "67, ";
		return;
	}

	g_ulTestRightCnt++;
}

//�޸Ĺ���ԱPIN ʧ�ܺ�����PIN ����У��
void CPublish_ToolDlg::SKF_Functional_Testing_Case_68()
{
	g_ulTestRightCnt++;
}

//�ô���PIN ���г���������Դ�����У��
void CPublish_ToolDlg::SKF_Functional_Testing_Case_69()
{
	CString sPinHash = "0001020304050607000102030405060700010203040506070001020304050607";
	CString sErrPinHash = "0807060504030201080706050403020108070605040302010807060504030202";

	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "67, ";
		return;
	}

	sVerSoPinHash = sErrPinHash;
	for (int i = 0; i < 6; i++)
	{
		SKF_VERIFY_SOPIN();
		if (sw == "9000")
		{
			g_ulTestErrCnt++;
			g_sTestErrList += "67, ";
			return;
		}
	}

	sVerSoPinHash = sPinHash;
	g_ulTestRightCnt++;
}

//ɾ��ȫ���Ѵ���Ӧ��
void CPublish_ToolDlg::SKF_Functional_Testing_Case_70()
{
	SKF_DELET_FILE();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "70, ";
		return;
	}

	g_ulTestRightCnt++;
}

///��DF�»�ȡ�豸��Ϣ��Ӧ����6985
void CPublish_ToolDlg::SKF_Functional_Testing_Case_71()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "71, ";
		return;
	}

	SKF_SELECT_DF0();

	
	sw = SendCommandGetValueOrSW(SKF_GET_DEV_INFO_CMD, SKF_FLAG);
	if (sw != "6613")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "71, ";
		return;
	}

	g_ulTestRightCnt++;
}

////��EF�»�ȡ�豸��Ϣ��Ӧ����6985
void CPublish_ToolDlg::SKF_Functional_Testing_Case_72()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "72, ";
		return;
	}

	SKF_SELECT_DF0();
	SKF_VERIFY_PIN();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "72, ";
		return;
	}

	SKF_CREATE_EF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "72, ";
		return;
	}

	
	sw = SendCommandGetValueOrSW(SKF_GET_DEV_INFO_CMD, SKF_FLAG);
	if (sw != "6613")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "72, ";
		return;
	}

	g_ulTestRightCnt++;
}

//��DF���豸��֤��Ӧ����6985
void CPublish_ToolDlg::SKF_Functional_Testing_Case_73()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "73, ";
		return;
	}

	SKF_SELECT_DF0();
	SKF_DEVICE_AUTH();
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "73, ";
		return;
	}

	g_ulTestRightCnt++;
}

//û�����ɵ�����������豸��֤��Ӧ����6989
void CPublish_ToolDlg::SKF_Functional_Testing_Case_74()
{
	CString sAuthVal, sTemp;
	BYTE authPlainData[16] = { 0 };
	BYTE authCipherData[16] = { 0 };
	BYTE asDevAuthKey[16] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };

	sAuthVal = SKF_DEVICE_AUTH_CMD;

	//ѡ��MF
	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);
	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);

	//��ȡ�����
	
	sw = SendCommandGetValueOrSW(SKF_GET_RAND_CMD, SKF_FLAG);
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "74, ";
		return;
	}

	//sm4���������
	sValue = "1122334455667788";
	CstringToByte(sValue, authPlainData);
	Crypto_ECB_SM4(authPlainData, 16, asDevAuthKey, 1, authCipherData);
	for (int i = 0; i< 16; i++)
	{
		sTemp.Format("%02x", authCipherData[i]);
		sAuthVal += sTemp;
	}
	sAuthVal.MakeUpper();

	//�����豸��֤
	
	sw = SendCommandGetValueOrSW(sAuthVal, SKF_FLAG);
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "74, ";
		return;
	}

	g_ulTestRightCnt++;
}

//��SM4���ܵ�����padding���ԣ�Ӧ����6988
void CPublish_ToolDlg::SKF_Functional_Testing_Case_75()
{
	CString sAuthVal, sTemp;
	BYTE authPlainData[16] = { 0 };
	BYTE authCipherData[16] = { 0 };
	BYTE asDevAuthKey[16] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };

	sAuthVal = SKF_DEVICE_AUTH_CMD;

	//ѡ��MF
	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);
	
	SendCommandGetValueOrSW(SELECT_FATHER, FIRST_FLAG);

	//��ȡ�����
	
	sw = SendCommandGetValueOrSW(SKF_GET_RAND_CMD, SKF_FLAG);
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "75, ";
		return;
	}

	//sm4���������
	CstringToByte(sValue, authPlainData);
	authPlainData[12] = 0x34;
	Crypto_ECB_SM4(authPlainData, 16, asDevAuthKey, 1, authCipherData);
	for (int i = 0; i< 16; i++)
	{
		sTemp.Format("%02x", authCipherData[i]);
		sAuthVal += sTemp;
	}
	sAuthVal.MakeUpper();

	//�����豸��֤
	
	sw = SendCommandGetValueOrSW(sAuthVal, SKF_FLAG);
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "75, ";
		return;
	}

	g_ulTestRightCnt++;
}

//��EF���޸��豸��ǩ��Ӧ����6985
void CPublish_ToolDlg::SKF_Functional_Testing_Case_76()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "76, ";
		return;
	}

	SKF_SELECT_DF0();
	SKF_VERIFY_PIN();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "76, ";
		return;
	}

	SKF_CREATE_EF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "76, ";
		return;
	}

	SKF_SELECT_EF0();
	CString sLable = SKF_SET_DEV_INFO_CMD;
	CString sTemp;
	BYTE asLable[32] = { "aaaaaaaa" };

	for (int i = 0; i< 32; i++)
	{
		sTemp.Format("%02x", asLable[i]);
		sLable += sTemp;
	}
	sLable.MakeUpper();

	
	sw = SendCommandGetValueOrSW(sLable, SKF_FLAG);
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "76, ";
		return;
	}

	g_ulTestRightCnt++;
}

//��DF���޸��豸��ǩ��Ӧ����6985
void CPublish_ToolDlg::SKF_Functional_Testing_Case_77()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "77, ";
		return;
	}

	SKF_SELECT_DF0();
	SKF_VERIFY_PIN();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "77, ";
		return;
	}

	CString sLable = SKF_SET_DEV_INFO_CMD;
	CString sTemp;
	BYTE asLable[32] = { "aaaaaaaa" };

	for (int i = 0; i< 32; i++)
	{
		sTemp.Format("%02x", asLable[i]);
		sLable += sTemp;
	}
	sLable.MakeUpper();

	
	sw = SendCommandGetValueOrSW(sLable, SKF_FLAG);
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "77, ";
		return;
	}

	g_ulTestRightCnt++;
}

//��MF�������ȫ״̬��Ӧ����6985
void CPublish_ToolDlg::SKF_Functional_Testing_Case_78()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_SELECT_MF();

	
	sw = SendCommandGetValueOrSW("84EC03000100", SKF_FLAG);
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "78, ";
		return;
	}

	g_ulTestRightCnt++;
}

//��EF�������ȫ״̬��Ӧ����6985
void CPublish_ToolDlg::SKF_Functional_Testing_Case_79()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "79, ";
		return;
	}

	SKF_SELECT_DF0();
	SKF_VERIFY_PIN();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "79, ";
		return;
	}

	SKF_CREATE_EF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "79, ";
		return;
	}

	SKF_SELECT_EF0();
	
	sw = SendCommandGetValueOrSW("84EC03000100", SKF_FLAG);
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "79, ";
		return;
	}

	g_ulTestRightCnt++;
}

//����MF ����DF/EF�����޸��豸��֤��Կ��Ӧ����6985
void CPublish_ToolDlg::SKF_Functional_Testing_Case_80()
{
	BYTE asTemp[16] = { 0 };

	memcpy(asTemp, g_aCurDevAuthKey, 16);

	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "80, ";
		return;
	}

	SKF_SELECT_DF0();
	SKF_MODIFY_DEV_AUTH_KEY();
	memcpy(g_aCurDevAuthKey, asTemp, 16);
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "80, ";
		return;
	}

	g_ulTestRightCnt++;
}

//û�豸��֤���޸��豸��֤��Կ��Ӧ����6700
void CPublish_ToolDlg::SKF_Functional_Testing_Case_81()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();

	SKF_MODIFY_DEV_AUTH_KEY();
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "81, ";
		return;
	}

	g_ulTestRightCnt++;
}

//��ȡ���Ȳ�Ϊ8�ֽڱ����������
void CPublish_ToolDlg::SKF_Functional_Testing_Case_82()
{
	CString sCmd;

	sCmd = "0084000007";
	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "82, ";
		return;
	}

	g_ulTestRightCnt++;

}

//��ȡ����Ϊ0�������
void CPublish_ToolDlg::SKF_Functional_Testing_Case_83()
{
	CString sCmd;

	sCmd = "0084000000";
	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "83, ";
		return;
	}

	g_ulTestRightCnt++;
}

//����DF������rsa/sm2 key��Ӧ����6985
void CPublish_ToolDlg::SKF_Functional_Testing_Case_84()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_SELECT_MF();

	SKF_GENARATE_SM2_KEY_PAIR();
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "84, ";
		return;
	}

	g_ulTestRightCnt++;
}

//û���ð�ȫ�򻷾�����rsa/sm2 key��Ӧ����6985
void CPublish_ToolDlg::SKF_Functional_Testing_Case_85()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "85, ";
		return;
	}

	SKF_SELECT_DF0();
	SKF_VERIFY_PIN();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "85, ";
		return;
	}

	
	sw = SendCommandGetValueOrSW(SKF_GENARATE_SM2_KEY_PAIR_CMD, SKF_FLAG);
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "85, ";
		return;
	}

	g_ulTestRightCnt++;
}

//���ð�ȫ�򻷾��ˣ�����������key�İ�ȫ�򻷾���Ӧ����6985
void CPublish_ToolDlg::SKF_Functional_Testing_Case_86()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "86, ";
		return;
	}

	SKF_SELECT_DF0();
	SKF_VERIFY_PIN();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "86, ";
		return;
	}

	//��ȫ��������---����HASH
	
	sw = SendCommandGetValueOrSW("002201AA03870142", SKF_FLAG);
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "86, ";
		return;
	}

	
	sw = SendCommandGetValueOrSW(SKF_GENARATE_SM2_KEY_PAIR_CMD, SKF_FLAG);
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "86, ";
		return;
	}

	g_ulTestRightCnt++;
}

//����ģ��Ϊ2048b��RSAǩ����Կ
void CPublish_ToolDlg::SKF_Functional_Testing_Case_87()
{
	CString sCmd;

	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "87, ";
		return;
	}

	SKF_SELECT_DF0();
	SKF_VERIFY_PIN();

	//��ȫ��������������rsa��Կ��
	
	sw = SendCommandGetValueOrSW("002201B80483000200", SKF_FLAG);
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "87, ";
		return;
	}

	sCmd = "004600000208000001";
	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "87, ";
		return;
	}

	g_ulTestRightCnt++;
}

//����ģ��Ϊ4096b��RSAǩ����Կ
void CPublish_ToolDlg::SKF_Functional_Testing_Case_88()
{
	CString sCmd;

	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "88, ";
		return;
	}

	SKF_SELECT_DF0();
	SKF_VERIFY_PIN();

	//��ȫ��������������rsa��Կ��
	
	sw = SendCommandGetValueOrSW("002201B80483000200", SKF_FLAG);
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "88, ";
		return;
	}

	sCmd = "00460000021000";
	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "88, ";
		return;
	}

	g_ulTestRightCnt++;
}

//���������ڼ��ܹ�Կ
void CPublish_ToolDlg::SKF_Functional_Testing_Case_89()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "89, ";
		return;
	}

	SKF_SELECT_DF0();
	SKF_VERIFY_PIN();

	
	sw = SendCommandGetValueOrSW("80E60B1340", SKF_FLAG);
	/*if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "89, ";
		return;
	}*/

	g_ulTestRightCnt++;
}

//���ð�ȫ�򻷾���ѡ��Ĺ�ϣ�㷨����֧��
void CPublish_ToolDlg::SKF_Functional_Testing_Case_90()
{
	SKF_SELECT_MF();

	
	sw = SendCommandGetValueOrSW("002201AA03870102", SKF_FLAG);
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "90, ";
		return;
	}

	g_ulTestRightCnt++;
}

//���ð�ȫ�򻷾�---���ܣ�ѡ��Ĳ��뷽ʽ����֧��
void CPublish_ToolDlg::SKF_Functional_Testing_Case_91()
{
	SKF_SELECT_MF();

	
	sw = SendCommandGetValueOrSW("00 22 81 b8 07 80 01 84 83 02 00 00", SKF_FLAG);
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "91, ";
		return;
	}

	g_ulTestRightCnt++;

}

//���ð�ȫ�򻷾�---���ܣ�ѡ��Ĳ��뷽ʽ����֧��
void CPublish_ToolDlg::SKF_Functional_Testing_Case_92()
{
	SKF_SELECT_MF();

	
	sw = SendCommandGetValueOrSW("00 22 41 b8 07 80 01 84 83 02 00 00", SKF_FLAG);
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "92, ";
		return;
	}

	g_ulTestRightCnt++;
}

//��������ϣֵ��32B��
void CPublish_ToolDlg::SKF_Functional_Testing_Case_93()
{
	CString sHashData, sDataLen, sCmd;

	sHashData = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
	sDataLen = "20";

	//��ȫ��������---����HASH
	
	sw = SendCommandGetValueOrSW("002201AA03870142", SKF_FLAG);
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "93, ";
		return;
	}

	//hash_sm3_update
	sCmd = "102A9080";
	sCmd += sDataLen;
	sCmd += sHashData;
	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "93, ";
		return;
	}

	//hash_sm3_update
	sCmd = "102A9080";
	sCmd += sDataLen;
	sCmd += sHashData;
	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "93, ";
		return;
	}

	//hash_sm3_final
	sCmd = "002A908020";
	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "93, ";
		return;
	}

	g_ulTestRightCnt++;
}

//��������ϣֵ��128B��
void CPublish_ToolDlg::SKF_Functional_Testing_Case_94()
{
	CString sHashData, sDataLen, sCmd;

	sHashData = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
	sDataLen = "80";

	//��ȫ��������---����HASH
	
	sw = SendCommandGetValueOrSW("002201AA03870142", SKF_FLAG);
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "94, ";
		return;
	}

	//hash_sm3_update
	sCmd = "102A9080";
	sCmd += sDataLen;
	sCmd += sHashData;
	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "94, ";
		return;
	}

	//hash_sm3_update
	sCmd = "102A9080";
	sCmd += sDataLen;
	sCmd += sHashData;
	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "94, ";
		return;
	}

	//hash_sm3_final
	sCmd = "002A908020";
	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "94, ";
		return;
	}

	g_ulTestRightCnt++;

}

//���õ���Կ�Ҳ���ʱǩ��
void CPublish_ToolDlg::SKF_Functional_Testing_Case_95()
{
	CString sCmd;

	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	SKF_SELECT_DF0();
	SKF_VERIFY_PIN();

	SKF_HASH_SM3();

	//��ȫ��������----sm2ǩ��
	
	sw = SendCommandGetValueOrSW("002241B6078001428402130A", SKF_FLAG);

	//����ϣֵ����Ӳ����
	sCmd = "002A908120";
	sCmd += g_sHashValue;
	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);

	//SM2ǩ��
	sCmd = "002A9E0040";
	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	/*if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "95, ";
		return;
	}*/

	g_ulTestRightCnt++;
}

//��ȫ״̬������ʱǩ��
void CPublish_ToolDlg::SKF_Functional_Testing_Case_96()
{
	CString sCmd;

	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	SKF_SELECT_DF0();
	SKF_HASH_SM3();

	SKF_GENARATE_SM2_KEY_PAIR();

	//��ȫ��������----sm2ǩ��
	
	sw = SendCommandGetValueOrSW("002241B6078001428402120A", SKF_FLAG);

	//����ϣֵ����Ӳ����
	sCmd = "002A908120";
	sCmd += g_sHashValue;
	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);

	//SM2ǩ��
	sCmd = "002A9E0040";
	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "96, ";
		return;
	}

	g_ulTestRightCnt++;
}

//������ѡ���ļ�
void CPublish_ToolDlg::SKF_Functional_Testing_Case_97()
{
	g_ulTestRightCnt++;
}

//���ļ�
void CPublish_ToolDlg::SKF_Functional_Testing_Case_98()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	SKF_SELECT_DF0();
	SKF_VERIFY_PIN();
	SKF_CREATE_EF0();
	SKF_SELECT_EF0();

	SKF_READ_FILE();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "98, ";
		return;
	}

	g_ulTestRightCnt++;
}

// ����512Byte������Ϣ����������
void CPublish_ToolDlg::SKF_Functional_Testing_Case_99()
{
	CString sCmd, sTnitVector, sRelVecLen, sPadTyp, sFeedBit, sSm4Key, sKeyLen, sSrcLen, sSrc;

	//set_sym_mac_mode
	/*sCmd = "80D2001038";
	sTnitVector = "0001020304050607000102030405060700000000000000000000000000000000";
	sRelVecLen = "0000000000000010";
	sPadTyp = "0000000000000000";
	sFeedBit = "0000000000000000";*/
	sCmd = "80D200102C";
	sTnitVector = "0001020304050607000102030405060700000000000000000000000000000000";
	sRelVecLen = "00000010";
	sPadTyp = "00000000";
	sFeedBit = "00000000";
	sCmd += sTnitVector;
	sCmd += sRelVecLen;
	sCmd += sPadTyp;
	sCmd += sFeedBit;
	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "99, ";
		return;
	}

	//set_sym_sm4_plain_key
	sCmd = "C0D00000";
	sSm4Key = "06060606060606060606060606060606";
	sKeyLen = "10";
	sCmd += sKeyLen;
	sCmd += sSm4Key;
	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "99, ";
		return;
	}

	//mac_update
	sCmd = "80D71000";
	sSrc = "0505050505050505050505050505050505050505050505050505050505050506";
	sSrcLen = "20";
	sCmd += sSrcLen;
	sCmd += sSrc;
	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "99, ";
		return;
	}

	//mac_update
	sCmd = "80D71000";
	sSrc = "0505050505050505050505050505050505050505050505050505050505050506";
	sSrcLen = "20";
	sCmd += sSrcLen;
	sCmd += sSrc;
	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "99, ";
		return;
	}

	//mac_final
	sCmd = "80D7000010";
	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "99, ";
		return;
	}

	g_ulTestRightCnt++;
}

//��ȫ״̬������ʱ����SM4��Կ����ʽΪRSA ���ģ�
void CPublish_ToolDlg::SKF_Functional_Testing_Case_100()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	SKF_SELECT_DF0();

	SKF_SYM_SET_KEY_RSA();
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "100, ";
		return;
	}

	g_ulTestRightCnt++;
}

//����DF������SM4��Կ����ʽΪRSA ���ģ�
void CPublish_ToolDlg::SKF_Functional_Testing_Case_101()
{
	SKF_SELECT_MF();

	SKF_SYM_SET_KEY_RSA();
	if (sw == "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "101, ";
		return;
	}

	g_ulTestRightCnt++;
}

//key ������ʱ���ûỰ��Կ����ʽΪRSA ���ģ�
void CPublish_ToolDlg::SKF_Functional_Testing_Case_102()
{
	CString sCmd, sTemp;
	CString sSM4Key = "09090909090909090909090909090909";
	BYTE aPlainData[16] = { 0 };
	BYTE aCipherData[128] = { 0 };
	BYTE aRsaKeyMod[256] = { 0 };
	BYTE aRsaPubExp[4] = { 0x00, 0x01, 0x00, 0x01 };
	CstringToByte(sSM4Key, aPlainData);

	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	SKF_VERIFY_PIN();
	SKF_GENARATE_RSA_KEY_PAIR();

	//��ȡRSA��Կ
	
	sw = SendCommandGetValueOrSW("80E61B0280", SKF_FLAG);
	if (sw != "9000")
	{
		ShowMessageString("EXPORT RSA PUB KEY ERROR");
		ShowMessageString(sw);
		return;
	}

	CstringToByte(sValue, &aRsaKeyMod[128]);

	rsa_pub_pkcs1_encrypt2(aRsaKeyMod, aRsaPubExp, aPlainData, aCipherData, 16);
	sCmd = "C0 D0 00 01 81 02";  //TODO
	for (int i = 0; i< 128; i++)
	{
		sTemp.Format("%02x", aCipherData[i]);
		sCmd += sTemp;
	}
	sCmd.MakeUpper();

	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "102, ";
		return;
	}

	g_ulTestRightCnt++;
}

//���ûỰ��Կ
void CPublish_ToolDlg::SKF_Functional_Testing_Case_103()
{
	CString sCmd, sTemp;
	CString sSM4Key = "09090909090909090909090909090909";
	BYTE aPlainData[16] = { 0 };
	BYTE aCipherData[128] = { 0 };
	BYTE aRsaKeyMod[256] = { 0 };
	BYTE aRsaPubExp[4] = { 0x00, 0x01, 0x00, 0x01 };
	CstringToByte(sSM4Key, aPlainData);

	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	SKF_SELECT_DF0();
	SKF_VERIFY_PIN();

	SKF_GENARATE_RSA_KEY_PAIR();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "103, ";
		return;
	}

	SKF_EXPORT_PSA_PUB_KEY();
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "103, ";
		return;
	}

	CstringToByte(sValue, &aRsaKeyMod[128]);

	int ret = rsa_pub_pkcs1_encrypt2(aRsaKeyMod, aRsaPubExp, aPlainData, aCipherData, 16);
	sCmd = "C0 D0 00 01 81 02";
	for (int i = 0; i< 128; i++)
	{
		sTemp.Format("%02x", aCipherData[i]);
		sCmd += sTemp;
	}
	sCmd.MakeUpper();

	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "103, ";
		return;
	}

	g_ulTestRightCnt++;
}

//����ECBģʽ
void CPublish_ToolDlg::SKF_Functional_Testing_Case_104()
{
	CString sCmd, sSm4Mode, sTnitVector, sRelVecLen, sPadTyp, sFeedBit;

	sCmd = SKF_SET_MODE_CMD;
	sSm4Mode = "01"; //01:ECB 02:CBC 04:CFB 08:OFB 10:MAC
	sCmd += sSm4Mode;
	sCmd += "38";
	sTnitVector = "0202020202020202020202020202020200000000000000000000000000000000";
	sRelVecLen = "0000000000000010";
	sPadTyp = "0000000000000000";
	sFeedBit = "0000000000000000";
	sCmd += sTnitVector;
	sCmd += sRelVecLen;
	sCmd += sPadTyp;
	sCmd += sFeedBit;
	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "104, ";
		return;
	}

	g_ulTestRightCnt++;
}

//����CBCģʽ
void CPublish_ToolDlg::SKF_Functional_Testing_Case_105()
{
	CString sCmd, sSm4Mode, sTnitVector, sRelVecLen, sPadTyp, sFeedBit;

	sCmd = SKF_SET_MODE_CMD;
	sSm4Mode = "02"; //01:ECB 02:CBC 04:CFB 08:OFB 10:MAC
	sCmd += sSm4Mode;
	sCmd += "38";
	sTnitVector = "0202020202020202020202020202020200000000000000000000000000000000";
	sRelVecLen = "0000000000000010";
	sPadTyp = "0000000000000000";
	sFeedBit = "0000000000000000";
	sCmd += sTnitVector;
	sCmd += sRelVecLen;
	sCmd += sPadTyp;
	sCmd += sFeedBit;
	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "105, ";
		return;
	}

	g_ulTestRightCnt++;
}

//����CFBģʽ
void CPublish_ToolDlg::SKF_Functional_Testing_Case_106()
{
	CString sCmd, sSm4Mode, sTnitVector, sRelVecLen, sPadTyp, sFeedBit;

	sCmd = SKF_SET_MODE_CMD;
	sSm4Mode = "04"; //01:ECB 02:CBC 04:CFB 08:OFB 10:MAC
	sCmd += sSm4Mode;
	sCmd += "38";
	sTnitVector = "0202020202020202020202020202020200000000000000000000000000000000";
	sRelVecLen = "0000000000000010";
	sPadTyp = "0000000000000000";
	sFeedBit = "0000000000000000";
	sCmd += sTnitVector;
	sCmd += sRelVecLen;
	sCmd += sPadTyp;
	sCmd += sFeedBit;
	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "106, ";
		return;
	}

	g_ulTestRightCnt++;
}

//����OFBģʽ
void CPublish_ToolDlg::SKF_Functional_Testing_Case_107()
{
	CString sCmd, sSm4Mode, sTnitVector, sRelVecLen, sPadTyp, sFeedBit;

	sCmd = SKF_SET_MODE_CMD;
	sSm4Mode = "08"; //01:ECB 02:CBC 04:CFB 08:OFB 10:MAC
	sCmd += sSm4Mode;
	sCmd += "38";
	sTnitVector = "0202020202020202020202020202020200000000000000000000000000000000";
	sRelVecLen = "0000000000000010";
	sPadTyp = "0000000000000000";
	sFeedBit = "0000000000000000";
	sCmd += sTnitVector;
	sCmd += sRelVecLen;
	sCmd += sPadTyp;
	sCmd += sFeedBit;

	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "107, ";
		return;
	}

	g_ulTestRightCnt++;
}

//����MACģʽ
void CPublish_ToolDlg::SKF_Functional_Testing_Case_108()
{
	CString sCmd, sTnitVector, sRelVecLen, sPadTyp, sFeedBit;

	//set_sym_mac_mode
	sCmd = "80D2001038";
	sTnitVector = "0001020304050607000102030405060700000000000000000000000000000000";
	sRelVecLen = "0000000000000010";
	sPadTyp = "0000000000000000";
	sFeedBit = "0000000000000000";
	sCmd += sTnitVector;
	sCmd += sRelVecLen;
	sCmd += sPadTyp;
	sCmd += sFeedBit;
	
	sw = SendCommandGetValueOrSW(sCmd, SKF_FLAG);
	if (sw != "9000")
	{
		g_ulTestErrCnt++;
		g_sTestErrList += "108, ";
		return;
	}

	g_ulTestRightCnt++;
}


void CPublish_ToolDlg::SKF_Functional_Testing()
{
	int iCnt = 0;
	CString sTestCnt;

	m_mTestCnt.GetWindowTextA(sTestCnt);
	if (!sTestCnt.IsEmpty())
	{
		iCnt = atoi(sTestCnt.GetString());
	}

	for (int i = 0; i < iCnt; i++)
	{
		SKF_DELET_FILE();
		SKF_CREATE_MF();
		g_ulTestRightCnt = 0;
		g_ulTestErrCnt = 0;
		g_sTestErrList.Empty();
		SKF_Functional_Testing_Done();
		SKF_Functional_Testing_ShowResult(i + 1);
	}

	for (int i = 0; i < iCnt; i++)
	{
		SKF_DELET_FILE();
		SKF_CREATE_MF();
		g_ulPolTestRightCnt = 0;
		g_ulPolTestErrCnt = 0;
		g_sPolTestErrList.Empty();
		SKF_Police_Testing_Done();
		SKF_Police_Testing_ShowResult(i + 1);
	}
	
}

void CPublish_ToolDlg::SKF_Functional_Testing_ShowResult(int i)
{
	using namespace std;

	if ((g_ulTestRightCnt == 0) && (g_ulTestErrCnt == 0)) return;

	CString Message, sTemp;
	int len = m_mTestResult.GetWindowTextLengthA();

	ofstream osLogFile;
	CString sLogFile;

	SYSTEMTIME sTime;
	GetLocalTime(&sTime);

	sLogFile.Format("[%d-%02d-%02d %02d:%02d:%02d]Functional Test %d Result: RightCase %d, ErrorCase %d,  Error Case List: ",
		             sTime.wYear, sTime.wMonth, sTime.wDay, sTime.wHour, sTime.wMinute, sTime.wSecond, i, g_ulTestRightCnt, g_ulTestErrCnt);

	sLogFile += g_sTestErrList + "\r\n";

	osLogFile.open("veb_fun_test_result.log", ios::app);
	if (osLogFile.is_open())
	{
		osLogFile << sLogFile;
		osLogFile.close();
	}


	/*Test i Result: RightCase i, ErrorCase i  
	     Error Case: ...                      */
	Message.Format("Functional Test %d Result: RightCase %d, ErrorCase %d \r\n   Error Case List:", i, g_ulTestRightCnt, g_ulTestErrCnt);
	Message += g_sTestErrList;

	if ((len + Message.GetLength()) > (m_mTestResult.GetLimitText()))
	{
		m_mTestResult.SetWindowTextA(_T("Clear Screen ...\r\n"));
	}

	Message += "\r\n\r\n";

	m_mTestResult.SetSel(-1, -1);
	m_mTestResult.ReplaceSel(Message);
	m_mTestResult.PostMessageA(WM_VSCROLL, SB_BOTTOM, 0);

}

void CPublish_ToolDlg::SKF_Functional_Testing_Done()
{
	if (m_mCase1.GetCheck() == 1) {
		SKF_Functional_Testing_Case_1();
		m_mCase1.SetCheck(0);
	}
	if (m_mCase2.GetCheck() == 1) {
		SKF_Functional_Testing_Case_2();
		m_mCase2.SetCheck(0);
	}
	if (m_mCase3.GetCheck() == 1)
	{
		SKF_Functional_Testing_Case_3();
		m_mCase3.SetCheck(0);
	}
	if (m_mCase4.GetCheck() == 1) {
		SKF_Functional_Testing_Case_4();
		m_mCase4.SetCheck(0);
	}
	if (m_mCase5.GetCheck() == 1) {
		SKF_Functional_Testing_Case_5();
		m_mCase5.SetCheck(0);
	}
	if (m_mCase6.GetCheck() == 1) {
		SKF_Functional_Testing_Case_6();
		m_mCase6.SetCheck(0);
	}
	if (m_mCase7.GetCheck() == 1) {
		SKF_Functional_Testing_Case_7();
		m_mCase7.SetCheck(0);
	}
	if (m_mCase8.GetCheck() == 1) {
		SKF_Functional_Testing_Case_8();
		m_mCase8.SetCheck(0);
	}
	if (m_mCase9.GetCheck() == 1) {
		SKF_Functional_Testing_Case_9();
		m_mCase9.SetCheck(0);
	}
	if (m_mCase10.GetCheck() == 1) {
		SKF_Functional_Testing_Case_10();
		m_mCase10.SetCheck(0);
	}
	if (m_mCase11.GetCheck() == 1) {
		SKF_Functional_Testing_Case_11();
		m_mCase11.SetCheck(0);
	}
	if (m_mCase12.GetCheck() == 1) {
		SKF_Functional_Testing_Case_12();
		m_mCase12.SetCheck(0);
	}
	if (m_mCase13.GetCheck() == 1) {
		SKF_Functional_Testing_Case_13();
		m_mCase13.SetCheck(0);
	}
	if (m_mCase14.GetCheck() == 1) {
		SKF_Functional_Testing_Case_14();
		m_mCase14.SetCheck(0);
	}
	if (m_mCase15.GetCheck() == 1) {
		SKF_Functional_Testing_Case_15();
		m_mCase15.SetCheck(0);
	}
	if (m_mCase16.GetCheck() == 1) {
		SKF_Functional_Testing_Case_16();
		m_mCase16.SetCheck(0);
	}
	if (m_mCase17.GetCheck() == 1) {
		SKF_Functional_Testing_Case_17();
		m_mCase17.SetCheck(0);
	}
	if (m_mCase18.GetCheck() == 1) {
		SKF_Functional_Testing_Case_18();
		m_mCase18.SetCheck(0);
	}
	if (m_mCase19.GetCheck() == 1) {
		SKF_Functional_Testing_Case_19();
		m_mCase19.SetCheck(0);
	}
	if (m_mCase20.GetCheck() == 1) {
		SKF_Functional_Testing_Case_20();
		m_mCase20.SetCheck(0);
	}
	if (m_mCase21.GetCheck() == 1) {
		SKF_Functional_Testing_Case_21();
		m_mCase21.SetCheck(0);
	}
	if (m_mCase22.GetCheck() == 1) {
		SKF_Functional_Testing_Case_22();
		m_mCase22.SetCheck(0);
	}
	if (m_mCase23.GetCheck() == 1) {
		SKF_Functional_Testing_Case_23();
		m_mCase23.SetCheck(0);
	}
	if (m_mCase24.GetCheck() == 1) {
		SKF_Functional_Testing_Case_24();
		m_mCase24.SetCheck(0);
	}
	if (m_mCase25.GetCheck() == 1) {
		SKF_Functional_Testing_Case_25();
		m_mCase25.SetCheck(0);
	}
	if (m_mCase26.GetCheck() == 1) {
		SKF_Functional_Testing_Case_26();
		m_mCase26.SetCheck(0);
	}
	if (m_mCase27.GetCheck() == 1) {
		SKF_Functional_Testing_Case_27();
		m_mCase27.SetCheck(0);
	}
	if (m_mCase28.GetCheck() == 1) {
		SKF_Functional_Testing_Case_28();
		m_mCase28.SetCheck(0);
	}
	if (m_mCase29.GetCheck() == 1) {
		SKF_Functional_Testing_Case_29();
		m_mCase29.SetCheck(0);
	}
	if (m_mCase30.GetCheck() == 1) {
		SKF_Functional_Testing_Case_30();
		m_mCase30.SetCheck(0);
	}
	if (m_mCase31.GetCheck() == 1) {
		SKF_Functional_Testing_Case_31();
		m_mCase31.SetCheck(0);
	}
	if (m_mCase32.GetCheck() == 1) {
		SKF_Functional_Testing_Case_32();
		m_mCase32.SetCheck(0);
	}
	if (m_mCase33.GetCheck() == 1) {
		SKF_Functional_Testing_Case_33();
		m_mCase33.SetCheck(0);
	}
	if (m_mCase34.GetCheck() == 1) {
		SKF_Functional_Testing_Case_34();
		m_mCase34.SetCheck(0);
	}
	if (m_mCase35.GetCheck() == 1) {
		SKF_Functional_Testing_Case_35();
		m_mCase35.SetCheck(0);
	}
	if (m_mCase36.GetCheck() == 1) {
		SKF_Functional_Testing_Case_36();
		m_mCase36.SetCheck(0);
	}
	if (m_mCase37.GetCheck() == 1) {
		SKF_Functional_Testing_Case_37();
		m_mCase37.SetCheck(0);
	}
	if (m_mCase38.GetCheck() == 1) {
		SKF_Functional_Testing_Case_38();
		m_mCase38.SetCheck(0);
	}
	if (m_mCase39.GetCheck() == 1) {
		SKF_Functional_Testing_Case_39();
		m_mCase39.SetCheck(0);
	}
	if (m_mCase40.GetCheck() == 1) {
		SKF_Functional_Testing_Case_40();
		m_mCase40.SetCheck(0);
	}
	if (m_mCase41.GetCheck() == 1) {
		SKF_Functional_Testing_Case_41();
		m_mCase41.SetCheck(0);
	}
	if (m_mCase42.GetCheck() == 1) {
		SKF_Functional_Testing_Case_42();
		m_mCase42.SetCheck(0);
	}
	if (m_mCase43.GetCheck() == 1) {
		SKF_Functional_Testing_Case_43();
		m_mCase43.SetCheck(0);
	}
	if (m_mCase44.GetCheck() == 1) {
		SKF_Functional_Testing_Case_44();
		m_mCase44.SetCheck(0);
	}
	if (m_mCase45.GetCheck() == 1) {
		SKF_Functional_Testing_Case_45();
		m_mCase45.SetCheck(0);
	}
	if (m_mCase46.GetCheck() == 1) {
		SKF_Functional_Testing_Case_46();
		m_mCase46.SetCheck(0);
	}
	if (m_mCase47.GetCheck() == 1) {
		SKF_Functional_Testing_Case_47();
		m_mCase47.SetCheck(0);
	}
	if (m_mCase48.GetCheck() == 1) {
		SKF_Functional_Testing_Case_48();
		m_mCase48.SetCheck(0);
	}
	if (m_mCase49.GetCheck() == 1) {
		SKF_Functional_Testing_Case_49();
		m_mCase49.SetCheck(0);
	}
	if (m_mCase50.GetCheck() == 1) {
		SKF_Functional_Testing_Case_50();
		m_mCase50.SetCheck(0);
	}
	if (m_mCase51.GetCheck() == 1) {
		SKF_Functional_Testing_Case_51();
		m_mCase51.SetCheck(0);
	}
	if (m_mCase52.GetCheck() == 1) {
		SKF_Functional_Testing_Case_52();
		m_mCase52.SetCheck(0);
	}
	if (m_mCase53.GetCheck() == 1) {
		SKF_Functional_Testing_Case_53();
		m_mCase53.SetCheck(0);
	}
	if (m_mCase54.GetCheck() == 1) {
		SKF_Functional_Testing_Case_54();
		m_mCase54.SetCheck(0);
	}
	if (m_mCase55.GetCheck() == 1) {
		SKF_Functional_Testing_Case_55();
		m_mCase55.SetCheck(0);
	}
	if (m_mCase56.GetCheck() == 1) {
		SKF_Functional_Testing_Case_56();
		m_mCase56.SetCheck(0);
	}
	if (m_mCase57.GetCheck() == 1) {
		SKF_Functional_Testing_Case_57();
		m_mCase57.SetCheck(0);
	}
	if (m_mCase58.GetCheck() == 1) {
		SKF_Functional_Testing_Case_58();
		m_mCase58.SetCheck(0);
	}
	if (m_mCase59.GetCheck() == 1) {
		SKF_Functional_Testing_Case_59();
		m_mCase59.SetCheck(0);
	}
	if (m_mCase60.GetCheck() == 1) {
		SKF_Functional_Testing_Case_60();
		m_mCase60.SetCheck(0);
	}
	if (m_mCase61.GetCheck() == 1) {
		SKF_Functional_Testing_Case_61();
		m_mCase61.SetCheck(0);
	}
	if (m_mCase62.GetCheck() == 1) {
		SKF_Functional_Testing_Case_62();
		m_mCase62.SetCheck(0);
	}
	if (m_mCase63.GetCheck() == 1) {
		SKF_Functional_Testing_Case_63();
		m_mCase63.SetCheck(0);
	}
	if (m_mCase64.GetCheck() == 1) {
		SKF_Functional_Testing_Case_64();
		m_mCase64.SetCheck(0);
	}
	if (m_mCase65.GetCheck() == 1) {
		SKF_Functional_Testing_Case_65();
		m_mCase65.SetCheck(0);
	}
	if (m_mCase66.GetCheck() == 1) {
		SKF_Functional_Testing_Case_66();
		m_mCase66.SetCheck(0);
	}
	if (m_mCase67.GetCheck() == 1) {
		SKF_Functional_Testing_Case_67();
		m_mCase67.SetCheck(0);
	}
	if (m_mCase68.GetCheck() == 1) {
		SKF_Functional_Testing_Case_68();
		m_mCase68.SetCheck(0);
	}
	if (m_mCase69.GetCheck() == 1) {
		SKF_Functional_Testing_Case_69();
		m_mCase69.SetCheck(0);
	}
	if (m_mCase70.GetCheck() == 1) {
		SKF_Functional_Testing_Case_70();
		m_mCase70.SetCheck(0);
	}
	if (m_mCase71.GetCheck() == 1) {
		SKF_Functional_Testing_Case_71();
		m_mCase71.SetCheck(0);
	}
	if (m_mCase72.GetCheck() == 1) {
		SKF_Functional_Testing_Case_72();
		m_mCase72.SetCheck(0);
	}
	if (m_mCase73.GetCheck() == 1) {
		SKF_Functional_Testing_Case_73();
		m_mCase73.SetCheck(0);
	}
	if (m_mCase74.GetCheck() == 1) {
		SKF_Functional_Testing_Case_74();
		m_mCase74.SetCheck(0);
	}
	if (m_mCase75.GetCheck() == 1) {
		SKF_Functional_Testing_Case_75();
		m_mCase75.SetCheck(0);
	}
	if (m_mCase76.GetCheck() == 1) {
		SKF_Functional_Testing_Case_76();
		m_mCase76.SetCheck(0);
	}
	if (m_mCase77.GetCheck() == 1) {
		SKF_Functional_Testing_Case_77();
		m_mCase77.SetCheck(0);
	}
	if (m_mCase78.GetCheck() == 1) {
		SKF_Functional_Testing_Case_78();
		m_mCase78.SetCheck(0);
	}
	if (m_mCase79.GetCheck() == 1) {
		SKF_Functional_Testing_Case_79();
		m_mCase79.SetCheck(0);
	}
	if (m_mCase80.GetCheck() == 1) {
		SKF_Functional_Testing_Case_80();
		m_mCase80.SetCheck(0);
	}
	if (m_mCase81.GetCheck() == 1) {
		SKF_Functional_Testing_Case_81();
		m_mCase81.SetCheck(0);
	}
	if (m_mCase82.GetCheck() == 1) {
		SKF_Functional_Testing_Case_82();
		m_mCase82.SetCheck(0);
	}
	if (m_mCase83.GetCheck() == 1) {
		SKF_Functional_Testing_Case_83();
		m_mCase83.SetCheck(0);
	}
	if (m_mCase84.GetCheck() == 1) {
		SKF_Functional_Testing_Case_84();
		m_mCase84.SetCheck(0);
	}
	if (m_mCase85.GetCheck() == 1) {
		SKF_Functional_Testing_Case_85();
		m_mCase85.SetCheck(0);
	}
	if (m_mCase86.GetCheck() == 1) {
		SKF_Functional_Testing_Case_86();
		m_mCase86.SetCheck(0);
	}
	if (m_mCase87.GetCheck() == 1) {
		SKF_Functional_Testing_Case_87();
		m_mCase87.SetCheck(0);
	}
	if (m_mCase88.GetCheck() == 1) {
		SKF_Functional_Testing_Case_88();
		m_mCase88.SetCheck(0);
	}
	if (m_mCase89.GetCheck() == 1) {
		SKF_Functional_Testing_Case_89();
		m_mCase89.SetCheck(0);
	}
	if (m_mCase90.GetCheck() == 1) {
		SKF_Functional_Testing_Case_90();
		m_mCase90.SetCheck(0);
	}
	if (m_mCase91.GetCheck() == 1) {
		SKF_Functional_Testing_Case_91();
		m_mCase91.SetCheck(0);
	}
	if (m_mCase92.GetCheck() == 1) {
		SKF_Functional_Testing_Case_92();
		m_mCase92.SetCheck(0);
	}
	if (m_mCase93.GetCheck() == 1) {
		SKF_Functional_Testing_Case_93();
		m_mCase93.SetCheck(0);
	}
	if (m_mCase94.GetCheck() == 1) {
		SKF_Functional_Testing_Case_94();
		m_mCase94.SetCheck(0);
	}
	if (m_mCase95.GetCheck() == 1) {
		SKF_Functional_Testing_Case_95();
		m_mCase95.SetCheck(0);
	}
	if (m_mCase96.GetCheck() == 1) {
		SKF_Functional_Testing_Case_96();
		m_mCase96.SetCheck(0);
	}
	if (m_mCase97.GetCheck() == 1) {
		SKF_Functional_Testing_Case_97();
		m_mCase97.SetCheck(0);
	}
	if (m_mCase98.GetCheck() == 1) {
		SKF_Functional_Testing_Case_98();
		m_mCase98.SetCheck(0);
	}
	if (m_mCase99.GetCheck() == 1) {
		SKF_Functional_Testing_Case_99();
		m_mCase99.SetCheck(0);
	}
	if (m_mCase100.GetCheck() == 1) {
		SKF_Functional_Testing_Case_100();
		m_mCase100.SetCheck(0);
	}
	if (m_mCase101.GetCheck() == 1) {
		SKF_Functional_Testing_Case_101();
		m_mCase101.SetCheck(0);
	}
	if (m_mCase102.GetCheck() == 1) {
		SKF_Functional_Testing_Case_102();
		m_mCase102.SetCheck(0);
	}
	if (m_mCase103.GetCheck() == 1) {
		SKF_Functional_Testing_Case_103();
		m_mCase103.SetCheck(0);
	}
	if (m_mCase104.GetCheck() == 1) {
		SKF_Functional_Testing_Case_104();
		m_mCase104.SetCheck(0);
	}
	if (m_mCase105.GetCheck() == 1) {
		SKF_Functional_Testing_Case_105();
		m_mCase105.SetCheck(0);
	}
	if (m_mCase106.GetCheck() == 1) {
		SKF_Functional_Testing_Case_106();
		m_mCase106.SetCheck(0);
	}
	if (m_mCase107.GetCheck() == 1) {
		SKF_Functional_Testing_Case_107();
		m_mCase107.SetCheck(0);
	}
	if (m_mCase108.GetCheck() == 1) {
		SKF_Functional_Testing_Case_108();
		m_mCase108.SetCheck(0);
	}
}








//ULONG g_ulPolTestRightCnt;
//ULONG g_ulPolTestErrCnt;
//CString g_sPolTestErrList;

//����Ӧ�ã�ѡ��Ӧ�ã�ɾ��Ӧ��
void CPublish_ToolDlg::SKF_Police_Testing_Case_1()
{
	SKF_DELET_FILE();
	if (sw != "9000")
	{
		g_ulPolTestErrCnt++;
		g_sPolTestErrList += "1, ";
		return;
	}

	SKF_CREATE_MF();
	if (sw != "9000")
	{
		g_ulPolTestErrCnt++;
		g_sPolTestErrList += "1, ";
		return;
	}

	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulPolTestErrCnt++;
		g_sPolTestErrList += "1, ";
		return;
	}

	SKF_SELECT_MF();

	SKF_DELET_DF0();
	if (sw != "9000")
	{
		g_ulPolTestErrCnt++;
		g_sPolTestErrList += "1, ";
		return;
	}

	g_ulPolTestRightCnt++;
}

//�����ļ���ѡ���ļ���ɾ���ļ�
void CPublish_ToolDlg::SKF_Police_Testing_Case_2()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulPolTestErrCnt++;
		g_sPolTestErrList += "2, ";
		return;
	}

	SKF_VERIFY_PIN();
	if (sw != "9000")
	{
		g_ulPolTestErrCnt++;
		g_sPolTestErrList += "2, ";
		return;
	}

	SKF_CREATE_EF0();
	if (sw != "9000")
	{
		g_ulPolTestErrCnt++;
		g_sPolTestErrList += "2, ";
		return;
	}

	SKF_SELECT_DF0();
	/*SKF_SELECT_DF0();
	SKF_SELECT_EF0();
	if (sw != "9000")
	{
		g_ulPolTestErrCnt++;
		g_sPolTestErrList += "2, ";
		return;
	}*/
	
	SKF_DELET_EF0();
	if (sw != "9000")
	{
		g_ulPolTestErrCnt++;
		g_sPolTestErrList += "2, ";
		return;
	}

	g_ulPolTestRightCnt++;
}

//֤�鵼�����(д�ļ�)
void CPublish_ToolDlg::SKF_Police_Testing_Case_3()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulPolTestErrCnt++;
		g_sPolTestErrList += "3, ";
		return;
	}

	SKF_VERIFY_PIN();
	if (sw != "9000")
	{
		g_ulPolTestErrCnt++;
		g_sPolTestErrList += "3, ";
		return;
	}

	SKF_CREATE_EF0();
	if (sw != "9000")
	{
		g_ulPolTestErrCnt++;
		g_sPolTestErrList += "3, ";
		return;
	}

	SKF_SELECT_EF0();
	SKF_WRITE_FILE();
	if (sw != "9000")
	{
		g_ulPolTestErrCnt++;
		g_sPolTestErrList += "3, ";
		return;
	}

	g_ulPolTestRightCnt++;
}

//֤�鵼������(���ļ�)
void CPublish_ToolDlg::SKF_Police_Testing_Case_4()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulPolTestErrCnt++;
		g_sPolTestErrList += "4, ";
		return;
	}

	SKF_VERIFY_PIN();
	if (sw != "9000")
	{
		g_ulPolTestErrCnt++;
		g_sPolTestErrList += "4, ";
		return;
	}

	SKF_CREATE_EF0();
	if (sw != "9000")
	{
		g_ulPolTestErrCnt++;
		g_sPolTestErrList += "4, ";
		return;
	}

	SKF_SELECT_EF0();
	SKF_READ_FILE();
	if (sw != "9000")
	{
		g_ulPolTestErrCnt++;
		g_sPolTestErrList += "4, ";
		return;
	}

	g_ulPolTestRightCnt++;
}

//��Կ�����ɲ���(RSA)
void CPublish_ToolDlg::SKF_Police_Testing_Case_5()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulPolTestErrCnt++;
		g_sPolTestErrList += "5, ";
		return;
	}

	SKF_VERIFY_PIN();
	if (sw != "9000")
	{
		g_ulPolTestErrCnt++;
		g_sPolTestErrList += "5, ";
		return;
	}

	SKF_GENARATE_RSA_KEY_PAIR();
	if (sw != "9000")
	{
		g_ulPolTestErrCnt++;
		g_sPolTestErrList += "5, ";
		return;
	}

	g_ulPolTestRightCnt++;
}

//��Կ�����ɲ���(ECC)
void CPublish_ToolDlg::SKF_Police_Testing_Case_6()
{
	SKF_DELET_FILE();
	SKF_CREATE_MF();
	SKF_CREATE_DF0();
	if (sw != "9000")
	{
		g_ulPolTestErrCnt++;
		g_sPolTestErrList += "6, ";
		return;
	}

	SKF_VERIFY_PIN();
	if (sw != "9000")
	{
		g_ulPolTestErrCnt++;
		g_sPolTestErrList += "6, ";
		return;
	}

	SKF_GENARATE_SM2_KEY_PAIR();
	if (sw != "9000")
	{
		g_ulPolTestErrCnt++;
		g_sPolTestErrList += "6, ";
		return;
	}

	g_ulPolTestRightCnt++;
}


void CPublish_ToolDlg::SKF_Police_Testing_ShowResult(int i)
{
	using namespace std;

	if ((g_ulPolTestRightCnt == 0) && (g_ulPolTestErrCnt == 0)) return;

	CString Message;
	int len = m_mTestResult.GetWindowTextLengthA();

	ofstream osLogFile;
	CString sLogFile;

	SYSTEMTIME sTime;
	GetLocalTime(&sTime);

	sLogFile.Format("[%d-%02d-%02d %02d:%02d:%02d]Police Test %d Result: RightCase %d, ErrorCase %d,  Error Case List: ",
		              sTime.wYear, sTime.wMonth, sTime.wDay, sTime.wHour, sTime.wMinute, sTime.wSecond, i, g_ulPolTestRightCnt, g_ulPolTestErrCnt);

	sLogFile += g_sPolTestErrList + "\r\n";

	osLogFile.open("veb_pol_test_result.log", ios::app);
	if (osLogFile.is_open())
	{
		osLogFile << sLogFile;
		osLogFile.close();
	}

	Message.Format("Police Test %d Result: RightCase %d, ErrorCase %d \r\n   Error Case List:", i, g_ulPolTestRightCnt, g_ulPolTestErrCnt);
	Message += g_sPolTestErrList;

	if ((len + Message.GetLength()) > (m_mTestResult.GetLimitText()))
	{
		m_mTestResult.SetWindowTextA(_T("Clear Screen ...\r\n"));
	}

	Message += "\r\n\r\n";

	m_mTestResult.SetSel(-1, -1);
	m_mTestResult.ReplaceSel(Message);
	m_mTestResult.PostMessageA(WM_VSCROLL, SB_BOTTOM, 0);

}

void CPublish_ToolDlg::SKF_Police_Testing_Done()
{
	if (m_mPoliceCase1.GetCheck() == 1) {
		SKF_Police_Testing_Case_1();
		m_mPoliceCase1.SetCheck(0);
	}
	if (m_mPoliceCase2.GetCheck() == 1) {
		SKF_Police_Testing_Case_2();
		m_mPoliceCase2.SetCheck(0);
	}
	if (m_mPoliceCase3.GetCheck() == 1) {
		SKF_Police_Testing_Case_3();
		m_mPoliceCase3.SetCheck(0);
	}
	if (m_mPoliceCase4.GetCheck() == 1) {
		SKF_Police_Testing_Case_4();
		m_mPoliceCase4.SetCheck(0);
	}
	if (m_mPoliceCase5.GetCheck() == 1) {
		SKF_Police_Testing_Case_5();
		m_mPoliceCase5.SetCheck(0);
	}
	if (m_mPoliceCase6.GetCheck() == 1) {
		SKF_Police_Testing_Case_6();
		m_mPoliceCase6.SetCheck(0);
	}

}





void CPublish_ToolDlg::OnBnClickedButtonFsSelectAll()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������

	CString str;

	GetDlgItem(IDC_BUTTON_FS_SELECT_ALL)->GetWindowTextA(str);

	if (str == _T("ȫѡ"))
	{
		m_mCreateFile.SetCheck(1);
		m_mDeleteFile.SetCheck(1);
		m_mSelectFile.SetCheck(1);
		m_mReadFile.SetCheck(1);
		m_mWriteFile.SetCheck(1);
		m_mGetFileList.SetCheck(1);
		m_mGetDevInfo.SetCheck(1);
		m_mSetDevInfo.SetCheck(1);

		GetDlgItem(IDC_BUTTON_FS_SELECT_ALL)->SetWindowTextA(_T("ȫ��ѡ"));
	}
	else if (str == _T("ȫ��ѡ"))
	{
		m_mCreateFile.SetCheck(0);
		m_mDeleteFile.SetCheck(0);
		m_mSelectFile.SetCheck(0);
		m_mReadFile.SetCheck(0);
		m_mWriteFile.SetCheck(0);
		m_mGetFileList.SetCheck(0);
		m_mGetDevInfo.SetCheck(0);
		m_mSetDevInfo.SetCheck(0);

		GetDlgItem(IDC_BUTTON_FS_SELECT_ALL)->SetWindowTextA(_T("ȫѡ"));
	}
	else
	{
		AfxMessageBox(_T("��ť���ֳ���, ��������ܷ�, ����������"));
	}





}


void CPublish_ToolDlg::OnBnClickedButtonBusnissSelectAll()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������

	CString str;

	GetDlgItem(IDC_BUTTON_BUSNISS_SELECT_ALL)->GetWindowTextA(str);

	if (str == _T("ȫѡ"))
	{
		m_mGetRand.SetCheck(1);
		m_mDeviceAuth.SetCheck(1);
		m_mModifyPin.SetCheck(1);
		m_mGetSessionKey.SetCheck(1);
		m_mVerifyPin.SetCheck(1);
		m_mUnBlockResetPin.SetCheck(1);
		m_mImportPubKey.SetCheck(1);
		m_mImportKey.SetCheck(1);
		m_mDeletKey.SetCheck(1);
		m_mSessionKeyAlg.SetCheck(1);
		m_mSetMode.SetCheck(1);
		m_mSymMac.SetCheck(1);
		m_mSymEncrypt.SetCheck(1);
		m_mSymDecrypt.SetCheck(1);

		GetDlgItem(IDC_BUTTON_BUSNISS_SELECT_ALL)->SetWindowTextA(_T("ȫ��ѡ"));
	}
	else if (str == _T("ȫ��ѡ"))
	{
		m_mGetRand.SetCheck(0);
		m_mDeviceAuth.SetCheck(0);
		m_mModifyPin.SetCheck(0);
		m_mGetSessionKey.SetCheck(0);
		m_mVerifyPin.SetCheck(0);
		m_mUnBlockResetPin.SetCheck(0);
		m_mImportPubKey.SetCheck(0);
		m_mImportKey.SetCheck(0);
		m_mDeletKey.SetCheck(0);
		m_mSessionKeyAlg.SetCheck(0);
		m_mSetMode.SetCheck(0);
		m_mSymMac.SetCheck(0);
		m_mSymEncrypt.SetCheck(0);
		m_mSymDecrypt.SetCheck(0);

		GetDlgItem(IDC_BUTTON_BUSNISS_SELECT_ALL)->SetWindowTextA(_T("ȫѡ"));
	}
	else
	{
		AfxMessageBox(_T("��ť���ֳ���, ��������ܷ�, ����������"));
	}
}


void CPublish_ToolDlg::OnBnClickedButtonIkiselectAll()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������

	CString str;

	GetDlgItem(IDC_BUTTON_IKI_SELECT_ALL)->GetWindowTextA(str);

	if (str == _T("ȫѡ"))
	{
		m_mCase1.SetCheck(1);
		m_mCase2.SetCheck(1);
		m_mCase3.SetCheck(1);
		m_mCase4.SetCheck(1);
		m_mCase5.SetCheck(1);
		m_mCase6.SetCheck(1);
		m_mCase7.SetCheck(1);
		m_mCase8.SetCheck(1);
		m_mCase9.SetCheck(1);
		m_mCase10.SetCheck(1);
		m_mCase11.SetCheck(1);
		m_mCase12.SetCheck(1);
		m_mCase13.SetCheck(1);
		m_mCase14.SetCheck(1);
		m_mCase15.SetCheck(1);
		m_mCase16.SetCheck(1);
		m_mCase17.SetCheck(1);
		m_mCase18.SetCheck(1);
		m_mCase19.SetCheck(1);
		m_mCase20.SetCheck(1);
		m_mCase21.SetCheck(1);
		m_mCase22.SetCheck(1);
		m_mCase23.SetCheck(1);
		m_mCase24.SetCheck(1);
		m_mCase25.SetCheck(1);
		m_mCase26.SetCheck(1);
		m_mCase27.SetCheck(1);
		m_mCase28.SetCheck(1);
		m_mCase29.SetCheck(1);
		m_mCase30.SetCheck(1);
		m_mCase31.SetCheck(1);
		m_mCase32.SetCheck(1);
		m_mCase33.SetCheck(1);
		m_mCase34.SetCheck(1);
		m_mCase35.SetCheck(1);
		m_mCase36.SetCheck(1);
		m_mCase37.SetCheck(1);
		m_mCase38.SetCheck(1);
		m_mCase39.SetCheck(1);
		m_mCase40.SetCheck(1);
		m_mCase41.SetCheck(1);
		m_mCase42.SetCheck(1);
		m_mCase43.SetCheck(1);
		m_mCase44.SetCheck(1);
		m_mCase45.SetCheck(1);
		m_mCase46.SetCheck(1);
		m_mCase47.SetCheck(1);
		m_mCase48.SetCheck(1);
		m_mCase49.SetCheck(1);
		m_mCase50.SetCheck(1);
		m_mCase51.SetCheck(1);
		m_mCase52.SetCheck(1);
		m_mCase53.SetCheck(1);
		m_mCase54.SetCheck(1);
		m_mCase55.SetCheck(1);
		m_mCase56.SetCheck(1);
		m_mCase57.SetCheck(1);
		m_mCase58.SetCheck(1);
		m_mCase59.SetCheck(1);
		m_mCase60.SetCheck(1);
		m_mCase61.SetCheck(1);
		m_mCase62.SetCheck(1);
		m_mCase63.SetCheck(1);
		m_mCase64.SetCheck(1);
		m_mCase65.SetCheck(1);
		m_mCase66.SetCheck(1);
		m_mCase67.SetCheck(1);
		m_mCase68.SetCheck(1);
		m_mCase69.SetCheck(1);
		m_mCase70.SetCheck(1);
		m_mCase71.SetCheck(1);
		m_mCase72.SetCheck(1);
		m_mCase73.SetCheck(1);
		m_mCase74.SetCheck(1);
		m_mCase75.SetCheck(1);
		m_mCase76.SetCheck(1);
		m_mCase77.SetCheck(1);
		m_mCase78.SetCheck(1);
		m_mCase79.SetCheck(1);
		m_mCase80.SetCheck(1);
		m_mCase81.SetCheck(1);
		m_mCase82.SetCheck(1);
		m_mCase83.SetCheck(1);
		m_mCase84.SetCheck(1);
		m_mCase85.SetCheck(1);
		m_mCase86.SetCheck(1);
		m_mCase87.SetCheck(1);
		m_mCase88.SetCheck(1);
		m_mCase89.SetCheck(1);
		m_mCase90.SetCheck(1);
		m_mCase91.SetCheck(1);
		m_mCase92.SetCheck(1);
		m_mCase93.SetCheck(1);
		m_mCase94.SetCheck(1);
		m_mCase95.SetCheck(1);
		m_mCase96.SetCheck(1);
		m_mCase97.SetCheck(1);
		m_mCase98.SetCheck(1);
		m_mCase99.SetCheck(1);
		m_mCase100.SetCheck(1);
		m_mCase101.SetCheck(1);
		m_mCase102.SetCheck(1);
		m_mCase103.SetCheck(1);
		m_mCase104.SetCheck(1);
		m_mCase105.SetCheck(1);
		m_mCase106.SetCheck(1);
		m_mCase107.SetCheck(1);
		m_mCase108.SetCheck(1);

		g_bLogON = TRUE;

		GetDlgItem(IDC_BUTTON_IKI_SELECT_ALL)->SetWindowTextA(_T("ȫ��ѡ"));
	}
	else if (str == _T("ȫ��ѡ"))
	{
		m_mCase1.SetCheck(0);
		m_mCase2.SetCheck(0);
		m_mCase3.SetCheck(0);
		m_mCase4.SetCheck(0);
		m_mCase5.SetCheck(0);
		m_mCase6.SetCheck(0);
		m_mCase7.SetCheck(0);
		m_mCase8.SetCheck(0);
		m_mCase9.SetCheck(0);
		m_mCase10.SetCheck(0);
		m_mCase11.SetCheck(0);
		m_mCase12.SetCheck(0);
		m_mCase13.SetCheck(0);
		m_mCase14.SetCheck(0);
		m_mCase15.SetCheck(0);
		m_mCase16.SetCheck(0);
		m_mCase17.SetCheck(0);
		m_mCase18.SetCheck(0);
		m_mCase19.SetCheck(0);
		m_mCase20.SetCheck(0);
		m_mCase21.SetCheck(0);
		m_mCase22.SetCheck(0);
		m_mCase23.SetCheck(0);
		m_mCase24.SetCheck(0);
		m_mCase25.SetCheck(0);
		m_mCase26.SetCheck(0);
		m_mCase27.SetCheck(0);
		m_mCase28.SetCheck(0);
		m_mCase29.SetCheck(0);
		m_mCase30.SetCheck(0);
		m_mCase31.SetCheck(0);
		m_mCase32.SetCheck(0);
		m_mCase33.SetCheck(0);
		m_mCase34.SetCheck(0);
		m_mCase35.SetCheck(0);
		m_mCase36.SetCheck(0);
		m_mCase37.SetCheck(0);
		m_mCase38.SetCheck(0);
		m_mCase39.SetCheck(0);
		m_mCase40.SetCheck(0);
		m_mCase41.SetCheck(0);
		m_mCase42.SetCheck(0);
		m_mCase43.SetCheck(0);
		m_mCase44.SetCheck(0);
		m_mCase45.SetCheck(0);
		m_mCase46.SetCheck(0);
		m_mCase47.SetCheck(0);
		m_mCase48.SetCheck(0);
		m_mCase49.SetCheck(0);
		m_mCase50.SetCheck(0);
		m_mCase51.SetCheck(0);
		m_mCase52.SetCheck(0);
		m_mCase53.SetCheck(0);
		m_mCase54.SetCheck(0);
		m_mCase55.SetCheck(0);
		m_mCase56.SetCheck(0);
		m_mCase57.SetCheck(0);
		m_mCase58.SetCheck(0);
		m_mCase59.SetCheck(0);
		m_mCase60.SetCheck(0);
		m_mCase61.SetCheck(0);
		m_mCase62.SetCheck(0);
		m_mCase63.SetCheck(0);
		m_mCase64.SetCheck(0);
		m_mCase65.SetCheck(0);
		m_mCase66.SetCheck(0);
		m_mCase67.SetCheck(0);
		m_mCase68.SetCheck(0);
		m_mCase69.SetCheck(0);
		m_mCase70.SetCheck(0);
		m_mCase71.SetCheck(0);
		m_mCase72.SetCheck(0);
		m_mCase73.SetCheck(0);
		m_mCase74.SetCheck(0);
		m_mCase75.SetCheck(0);
		m_mCase76.SetCheck(0);
		m_mCase77.SetCheck(0);
		m_mCase78.SetCheck(0);
		m_mCase79.SetCheck(0);
		m_mCase80.SetCheck(0);
		m_mCase81.SetCheck(0);
		m_mCase82.SetCheck(0);
		m_mCase83.SetCheck(0);
		m_mCase84.SetCheck(0);
		m_mCase85.SetCheck(0);
		m_mCase86.SetCheck(0);
		m_mCase87.SetCheck(0);
		m_mCase88.SetCheck(0);
		m_mCase89.SetCheck(0);
		m_mCase90.SetCheck(0);
		m_mCase91.SetCheck(0);
		m_mCase92.SetCheck(0);
		m_mCase93.SetCheck(0);
		m_mCase94.SetCheck(0);
		m_mCase95.SetCheck(0);
		m_mCase96.SetCheck(0);
		m_mCase97.SetCheck(0);
		m_mCase98.SetCheck(0);
		m_mCase99.SetCheck(0);
		m_mCase100.SetCheck(0);
		m_mCase101.SetCheck(0);
		m_mCase102.SetCheck(0);
		m_mCase103.SetCheck(0);
		m_mCase104.SetCheck(0);
		m_mCase105.SetCheck(0);
		m_mCase106.SetCheck(0);
		m_mCase107.SetCheck(0);
		m_mCase108.SetCheck(0);
		
		g_bLogON = TRUE;

		GetDlgItem(IDC_BUTTON_IKI_SELECT_ALL)->SetWindowTextA(_T("ȫѡ"));
	}
	else
	{
		AfxMessageBox(_T("��ť���ֳ���, ��������ܷ�, ����������"));
	}
	

}

void CPublish_ToolDlg::OnBnClickedButtonPolSelectAll()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������

	CString str;

	GetDlgItem(IDC_BUTTON_POL_SELECT_ALL)->GetWindowTextA(str);

	if (str == _T("ȫѡ"))
	{
		m_mPoliceCase1.SetCheck(1);
		m_mPoliceCase2.SetCheck(1);
		m_mPoliceCase3.SetCheck(1);
		m_mPoliceCase4.SetCheck(1);
		m_mPoliceCase5.SetCheck(1);
		m_mPoliceCase6.SetCheck(1);

		g_bLogON = FALSE;

		GetDlgItem(IDC_BUTTON_POL_SELECT_ALL)->SetWindowTextA(_T("ȫ��ѡ"));
	}
	else if (str == _T("ȫ��ѡ"))
	{
		m_mPoliceCase1.SetCheck(0);
		m_mPoliceCase2.SetCheck(0);
		m_mPoliceCase3.SetCheck(0);
		m_mPoliceCase4.SetCheck(0);
		m_mPoliceCase5.SetCheck(0);
		m_mPoliceCase6.SetCheck(0);

		g_bLogON = TRUE;

		GetDlgItem(IDC_BUTTON_POL_SELECT_ALL)->SetWindowTextA(_T("ȫѡ"));
	}
	else
	{
		AfxMessageBox(_T("��ť���ֳ���, ��������ܷ�, ����������"));
	}
}


void CPublish_ToolDlg::OnBnClickedButtonSendCmd()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	CString str, sRet;
	m_mSingleCmd.GetWindowTextA(str);

	if (str == "\0")
		AfxMessageBox(_T("������Ҫ�·���ָ��"));
	else {
		
		sRet = SendCommandGetValueOrSW(str, 1);

		if (sRet == "") {
			AfxMessageBox(_T("ָ���ʧ��"));
		}
	}
}



void CPublish_ToolDlg::OnBnClickedButtonGetCurrentState()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	CString sValue;

	ShowMessageString(_T("����״̬"));
	sValue = SendCommandGetValueOrSW("8006000001", 0);
	sValue = sValue.Left(2);

	m_mCurrentState.SetWindowTextA(sValue);

}


void CPublish_ToolDlg::OnBnClickedButtonSetState()
{

	// TODO: �ڴ���ӿؼ�֪ͨ����������

	CString str;
	m_mSetState.GetWindowTextA(str);

	if ((str != "70") && (str != "71") && (str != "72"))
	{
		AfxMessageBox(_T("״ֻ̬��Ϊ70, 71�� 72"));
		return;
	}


	ShowMessageString(_T("����״̬"));
	
	SendCommandGetValueOrSW("8006" + str + "0100", SKF_FLAG);

}





void CPublish_ToolDlg::OnBnClickedButtonSelect()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	TCHAR szFilter[] = _T("��ִ���ļ�(*.bin)|*.bin|�����ļ�(*.*)|*.*||");

	CFileDialog fileDlg(TRUE, NULL, NULL, 0, szFilter, this);

	if (IDOK == fileDlg.DoModal()) {
		g_strExtName = fileDlg.GetFileExt();

		if (g_strExtName != "bin") {
			AfxMessageBox(_T("��ѡ����ȷ���ļ�����(*.bin)"));
			return;
		}

		g_strFilePath = fileDlg.GetPathName();
		SetDlgItemText(IDC_EDIT_FILE_NAME, g_strFilePath);
	}
}


void CPublish_ToolDlg::OnBnClickedButtonDownload()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	GetDlgItemText(IDC_EDIT_FILE_NAME, g_strFilePath);

	BYTE readBuf[2048] = { 0 };
	UINT totalLen = 0, offset = 0, readLen = 0;

	if (g_strFilePath == "") {
		AfxMessageBox(_T("����ѡ��Ҫ���صĿ�ִ���ļ�(*.bin)"));
		return;
	}

	CStdioFile loadFile;
	CFileException fileException;

	if (!loadFile.Open(g_strFilePath, CFile::typeBinary | CFile::modeRead)) {
		AfxMessageBox(_T("�ļ���ʧ��, ������"));
		return;
	
	}

	CString sDisp, sTemp, sSW;
	BYTE hexCmd[8 * 1024] = {0x00, 0x04};
	WORD hexCmdLen = 0;
	BYTE RecvBuf[8 * 1024] = { 0 };
	unsigned long RecvBufLen = 4 * 1024;
	UINT Rtn = 0;


	sha1_context ctx;

	sha1_init(&ctx);
	sha1_starts(&ctx);

	while ((readLen = loadFile.Read(readBuf, 1024)) != 0) {
		offset = totalLen;
		totalLen += readLen;
		hexCmd[2] = (offset >> 24) & 0xFF;
		hexCmd[3] = (offset >> 16) & 0xFF;
		hexCmd[4] = (offset >>  8) & 0xFF;
		hexCmd[5] = (offset >>  0) & 0xFF;

		memcpy(&hexCmd[6], readBuf, readLen);
		hexCmdLen = 6 + readLen;

		sha1_update(&ctx, readBuf, readLen);



		sDisp = "-->: ";
		for (int i = 0; i < hexCmdLen; i++)
		{
			sTemp.Format("%02x", hexCmd[i]);
			sDisp += sTemp;
		}
		sDisp.MakeUpper();
		ShowMessageString(sDisp);

	ww:
		if (Rtn = m_pMeth->WriteDeviceData(hDevice, hexCmd, hexCmdLen))
		{
			AfxMessageBox(_T("д���ݵ��豸ʧ�ܣ�"));
			goto err;
		}
		do
		{
			if (Rtn = m_pMeth->ReadDeviceData(hDevice, RecvBuf, &RecvBufLen))
			{
				if (Rtn == DR_RD_BUSY)
				{
					//Sleep(10);
					continue;
				}
				else if (Rtn == DR_RD_DATA)
				{
					goto ww;
				}
				else
				{
					AfxMessageBox(_T("���豸������ʧ�ܣ�"));
					goto err;
				}
			}
			else {
				break;
			}

		} while (1);


		sDisp = "<--: ";
		sSW = "";
		for (int i = 0; i < RecvBufLen; i++)
		{
			sTemp.Format("%02x", RecvBuf[i]);
			sDisp += sTemp;

			if (i >= (RecvBufLen - 2))
			{
				sSW += sTemp;
			}
		}
		sDisp.Insert(sDisp.GetLength() - 4, "  ");
		sDisp.MakeUpper();

		if (sSW == "9000") {
			ShowMessageString(sDisp);
		}
		else {
			ShowMessageStringAlert(sDisp, COLOR_RED);
			AfxMessageBox(_T("���س��ִ���, ������"));
			goto err;
		}
	}


	sha1_finish(&ctx, g_sha1Buf);
	sDisp = "";
	for (int i = 0; i < 20; i++)
	{
		sTemp.Format("%02x", g_sha1Buf[i]);
		sDisp += sTemp;
	}
	SetDlgItemText(IDC_EDIT_SHA1, sDisp);
	g_fileLen = totalLen;
	ShowMessageString(_T("���سɹ�"));
	return;


err:
	m_pMeth->CloseDevice(hDevice);
	return;

}


void CPublish_ToolDlg::OnBnClickedButtonSetAddr()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	CString strAddr; 
	GetDlgItemText(IDC_EDIT_ADDR, strAddr);
	strAddr.Remove(' ');
	strAddr = strAddr.Right(8);

	CString sDisp, sTemp, sSW;
	BYTE hexCmd[8 * 1024] = { 0x00, 0x03 };
	WORD hexCmdLen = 0;
	BYTE RecvBuf[8 * 1024] = { 0 };
	unsigned long RecvBufLen = 4 * 1024;
	UINT Rtn = 0;

	CstringToByte(strAddr, &hexCmd[2]);
	hexCmdLen = 6;

	sDisp = "-->: ";
	for (int i = 0; i < hexCmdLen; i++)
	{
		sTemp.Format("%02x", hexCmd[i]);
		sDisp += sTemp;
	}
	sDisp.MakeUpper();
	ShowMessageString(sDisp);

ww:
	if (Rtn = m_pMeth->WriteDeviceData(hDevice, hexCmd, hexCmdLen))
	{
		AfxMessageBox(_T("д���ݵ��豸ʧ�ܣ�"));
		goto err;
	}
	do
	{
		if (Rtn = m_pMeth->ReadDeviceData(hDevice, RecvBuf, &RecvBufLen))
		{
			if (Rtn == DR_RD_BUSY)
			{
				//Sleep(10);
				continue;
			}
			else if (Rtn == DR_RD_DATA)
			{
				goto ww;
			}
			else
			{
				AfxMessageBox(_T("���豸������ʧ�ܣ�"));
				goto err;
			}
		}
		else {
			break;
		}

	} while (1);


	sDisp = "<--: ";
	for (int i = 0; i < RecvBufLen; i++)
	{
		sTemp.Format("%02x", RecvBuf[i]);
		sDisp += sTemp;

		if (i >= (RecvBufLen - 2))
		{
			sSW += sTemp;
		}
	}
	sDisp.Insert(sDisp.GetLength() - 4, "  ");
	sDisp.MakeUpper();

	if (sSW == "9000") {
		ShowMessageString(sDisp);
	}
	else {
		ShowMessageStringAlert(sDisp, COLOR_RED);
		AfxMessageBox(_T("������¼��ַʧ��, ������"));
		goto err;
	}

	ShowMessageString(_T("������¼��ַ�ɹ�"));
	return;

err:
	m_pMeth->CloseDevice(hDevice);
	return;
}


void CPublish_ToolDlg::OnBnClickedButtonVerifySha1()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	CString strSha1;
	GetDlgItemText(IDC_EDIT_SHA1, strSha1);

	if (strSha1 == "") {
		AfxMessageBox(_T("�������ؿ�ִ���ļ�"));
		return;
	}


	CString sDisp, sTemp, sSW;
	BYTE hexCmd[8 * 1024] = { 0x00, 0x05 };
	WORD hexCmdLen = 0;
	BYTE RecvBuf[8 * 1024] = { 0 };
	unsigned long RecvBufLen = 4 * 1024;
	UINT Rtn = 0;

	hexCmd[2] = (g_fileLen >> 24) & 0xFF;
	hexCmd[3] = (g_fileLen >> 16) & 0xFF;
	hexCmd[4] = (g_fileLen >>  8) & 0xFF;
	hexCmd[5] = (g_fileLen >>  0) & 0xFF;

	memcpy(&hexCmd[6], g_sha1Buf, 20);
	hexCmdLen = 26;

	sDisp = "-->: ";
	for (int i = 0; i < hexCmdLen; i++)
	{
		sTemp.Format("%02x", hexCmd[i]);
		sDisp += sTemp;
	}
	sDisp.MakeUpper();
	ShowMessageString(sDisp);

ww:
	if (Rtn = m_pMeth->WriteDeviceData(hDevice, hexCmd, hexCmdLen))
	{
		AfxMessageBox(_T("д���ݵ��豸ʧ�ܣ�"));
		goto err;
	}
	do
	{
		if (Rtn = m_pMeth->ReadDeviceData(hDevice, RecvBuf, &RecvBufLen))
		{
			if (Rtn == DR_RD_BUSY)
			{
				//Sleep(10);
				continue;
			}
			else if (Rtn == DR_RD_DATA)
			{
				goto ww;
			}
			else
			{
				AfxMessageBox(_T("���豸������ʧ�ܣ�"));
				goto err;
			}
		}
		else {
			break;
		}

	} while (1);


	sDisp = "<--: ";
	for (int i = 0; i < RecvBufLen; i++)
	{
		sTemp.Format("%02x", RecvBuf[i]);
		sDisp += sTemp;

		if (i >= (RecvBufLen - 2))
		{
			sSW += sTemp;
		}
	}
	sDisp.Insert(sDisp.GetLength() - 4, "  ");
	sDisp.MakeUpper();

	if (sSW == "9000") {
		ShowMessageString(sDisp);
	}
	else {
		ShowMessageStringAlert(sDisp, COLOR_RED);
		AfxMessageBox(_T("У���ϣʧ��, ������"));
		goto err;
	}

	ShowMessageString(_T("У���ϣ�ɹ�"));
	return;

err:
	m_pMeth->CloseDevice(hDevice);
	return;




}


void CPublish_ToolDlg::OnBnClickedButtonReadFlash()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	CString strSavePath;
	GetDlgItemText(IDC_EDIT_SAVE_PATH, strSavePath);

	BYTE readBuf[2048] = { 0 };
	UINT totalLen = 0, offset = 0, readLen = 0;

	if (strSavePath == "") {
		AfxMessageBox(_T("����ѡ��Ҫ�����·��"));
		return;
	}

	CStdioFile saveFile;
	CFileException fileException;

	if (!saveFile.Open(strSavePath, CFile::modeCreate | CFile::typeText | CFile::modeWrite)) {
		AfxMessageBox(_T("�ļ���ʧ��, ������"));
		return;
	}

	CString sDisp, sTemp, sSW, strContent;
	BYTE hexCmd[8 * 1024] = { 0x06, 0x80, 0x80, 0x00, 0x00, 0x08, 0x00, 0x03, 0x20, 0x00, 0x00, 0x00, 0x04, 0x00};
	WORD hexCmdLen = 0;
	BYTE RecvBuf[8 * 1024] = { 0 };
	unsigned long RecvBufLen = 4 * 1024;
	UINT Rtn = 0;

	UINT addr = 0x00032000;

	//�ļ�ϵͳ�� 260K, ÿ�ζ� 1024 �ֽ�, �� 260 ��  by Huihh 2019.07.01
	for (int i = 0; i < 260; i++) {
		hexCmd[6] = (addr >> 24) & 0xFF;
		hexCmd[7] = (addr >> 16) & 0xFF;
		hexCmd[8] = (addr >>  8) & 0xFF;
		hexCmd[9] = (addr >>  0) & 0xFF;

		addr += 0x400;

		hexCmdLen = 14; //Type(1) + Cla(1) + Ins(1) + P1P2(2) + Lc(1) + Addr(4) + Len(4)    by Huihh 2019.07.01


		sDisp = "-->: ";
		for (int i = 0; i < (hexCmdLen - 1); i++)
		{
			sTemp.Format("%02x", hexCmd[i+1]);
			sDisp += sTemp;
		}
		sDisp.MakeUpper();
		ShowMessageString(sDisp);
	
	ww:
		if (Rtn = m_pMeth->WriteDeviceData(hDevice, hexCmd, hexCmdLen))
		{
			AfxMessageBox(_T("д���ݵ��豸ʧ�ܣ�"));
			goto err;
		}
		do
		{
			if (Rtn = m_pMeth->ReadDeviceData(hDevice, RecvBuf, &RecvBufLen))
			{
				if (Rtn == DR_RD_BUSY)
				{
					//Sleep(10);
					continue;
				}
				else if (Rtn == DR_RD_DATA)
				{
					goto ww;
				}
				else
				{
					AfxMessageBox(_T("���豸������ʧ�ܣ�"));
					goto err;
				}
			}
			else {
				break;
			}

		} while (1);


		sDisp = "<--: ";
		sSW = "";
		strContent = "";
		for (int i = 0; i < RecvBufLen; i++)
		{
			sTemp.Format("%02x", RecvBuf[i]);
			sDisp += sTemp;

			if (i >= (RecvBufLen - 2)) {
				sSW += sTemp;
			}
			else {
				strContent += sTemp;
			}

		}
		sDisp.Insert(sDisp.GetLength() - 4, "  ");
		sDisp.MakeUpper();

		if (sSW == "9000") {

			saveFile.Write(strContent, strContent.GetLength());
			ShowMessageString(sDisp);
		}
		else {
			ShowMessageStringAlert(sDisp, COLOR_RED);
			AfxMessageBox(_T("�� FLASH ���ִ���, ������"));
			goto err;
		}
	}

	saveFile.Close();
	ShowMessageString(_T("�� FLASH �ɹ�"));
	return;


err:
	m_pMeth->CloseDevice(hDevice);
	return;
}


void CPublish_ToolDlg::OnBnClickedButtonSelectPath()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������

	CString strSavePath;

	TCHAR szFilter[] = _T("�ı��ļ�(*.txt)|*.txt|�����ļ�(*.*)|*.*||");

	CFileDialog fileDlg(FALSE, "txt", NULL, 0, szFilter, this);

	if (IDOK == fileDlg.DoModal()) {
		g_strExtName = fileDlg.GetFileExt();

		if (g_strExtName != "txt") {
			AfxMessageBox(_T("��ѡ����ȷ�ı����ļ�����(*.txt)"));
			return;
		}

		strSavePath = fileDlg.GetPathName();
		SetDlgItemText(IDC_EDIT_SAVE_PATH, strSavePath);
	}
}
