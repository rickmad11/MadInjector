#include "pch.h"
#include "DownloadCallback.h"

HRESULT __stdcall DownloadCallback::GetBindInfo(DWORD* grfBINDF, BINDINFO* pbindinfo)
{
	return E_NOTIMPL;
}

HRESULT __stdcall DownloadCallback::GetPriority(long* pnPriority)
{
	return E_NOTIMPL;
}

HRESULT __stdcall DownloadCallback::OnDataAvailable(DWORD grfBSCF, DWORD dwSize, FORMATETC* pformatetc, STGMEDIUM* pstgmed)
{
	return E_NOTIMPL;
}

HRESULT __stdcall DownloadCallback::OnObjectAvailable(REFIID riid, IUnknown* punk)
{
	return E_NOTIMPL;
}

HRESULT __stdcall DownloadCallback::OnProgress(unsigned long ulProgress, unsigned long ulProgressMax, unsigned long ulStatusCode, LPCWSTR szStatusText)
{
	float fulProgress = static_cast<float>(ulProgress);
	float fulProgressMax = static_cast<float>(ulProgressMax);

	if(!ulProgressMax)
	{
		std::cout << '\r' << "0% " << "**********";
		return S_OK;
	}

	unsigned long progress_in_percent = static_cast<unsigned long>( (fulProgress / fulProgressMax) * 100.f );
	unsigned long temp_progress_in_percent = progress_in_percent;

	if(progress_in_percent > 10)
		while (progress_in_percent % 10 != 0)
			progress_in_percent -= 1;

	std::string progress;
	for (size_t index = 10; index <= 100; index += 10)
	{
		if (progress_in_percent % 10 == 0 && progress_in_percent > 0)
		{
			progress += '#';

			progress_in_percent -= 10;

			while (progress_in_percent % 10 != 0)
				progress_in_percent -= 1;

			continue;
		}
		progress += '*';
	}

	std::cout << '\r' << temp_progress_in_percent << "% " << progress;

	return S_OK;
}

HRESULT __stdcall DownloadCallback::OnStartBinding(DWORD dwReserved, IBinding* pib)
{
	return E_NOTIMPL;
}

HRESULT __stdcall DownloadCallback::OnStopBinding(HRESULT hresult, LPCWSTR szError)
{
	return E_NOTIMPL;
}

HRESULT __stdcall DownloadCallback::OnLowResource(DWORD reserved)
{
	return E_NOTIMPL;
}

HRESULT __stdcall DownloadCallback::QueryInterface(REFIID riid, void** ppvObject)
{
	return E_NOTIMPL;
}

ULONG __stdcall DownloadCallback::AddRef(void)
{
	return 0;
}

ULONG __stdcall DownloadCallback::Release(void)
{
	return 0;
}
