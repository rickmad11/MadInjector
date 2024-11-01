#pragma once

class DownloadCallback : public IBindStatusCallback
{
public:
	DownloadCallback() = default;

	DownloadCallback(DownloadCallback const&) = delete;
	DownloadCallback& operator=(DownloadCallback const&) = delete;

	DownloadCallback(DownloadCallback&&) = delete;
	DownloadCallback& operator=(DownloadCallback&&) = delete;

	virtual ~DownloadCallback() = default;

public:
	virtual HRESULT __stdcall GetBindInfo(DWORD* grfBINDF, BINDINFO* pbindinfo) override;
	virtual HRESULT __stdcall GetPriority(long* pnPriority) override;
	virtual HRESULT __stdcall OnDataAvailable(DWORD grfBSCF, DWORD dwSize, FORMATETC* pformatetc, STGMEDIUM* pstgmed) override;
	virtual HRESULT __stdcall OnObjectAvailable(REFIID riid, IUnknown* punk) override;
	virtual HRESULT __stdcall OnProgress(unsigned long ulProgress, unsigned long ulProgressMax, unsigned long ulStatusCode, LPCWSTR szStatusText) override;
	virtual HRESULT __stdcall OnStartBinding(DWORD dwReserved, IBinding* pib) override;
	virtual HRESULT __stdcall OnStopBinding(HRESULT hresult, LPCWSTR szError) override;
	virtual HRESULT __stdcall OnLowResource(DWORD reserved) override;

	virtual HRESULT __stdcall QueryInterface(REFIID riid, _COM_Outptr_ void __RPC_FAR* __RPC_FAR* ppvObject) override;
	virtual ULONG __stdcall AddRef(void) override;
	virtual ULONG __stdcall Release(void) override;
};

