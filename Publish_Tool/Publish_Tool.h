
// Publish_Tool.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CPublish_ToolApp:
// �йش����ʵ�֣������ Publish_Tool.cpp
//

class CPublish_ToolApp : public CWinApp
{
public:
	CPublish_ToolApp();

// ��д
public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CPublish_ToolApp theApp;