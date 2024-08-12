#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#define read_code CTL_CODE(FILE_DEVICE_UNKNOWN, 0x776, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define write_code CTL_CODE(FILE_DEVICE_UNKNOWN, 0x777, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

typedef struct info_t {
    HANDLE target_pid;
    ULONG64 target_address;
    PBYTE buffer_address;
    SIZE_T Size;
} UserData, * PUserData;

BOOL SendIoControlCode(HANDLE hDevice, DWORD dwIoControlCode, PVOID pInBuffer, DWORD nInBufferSize, PVOID pOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesReturned) {
    BOOL bResult = DeviceIoControl(
        hDevice,
        dwIoControlCode,
        pInBuffer,
        nInBufferSize,
        pOutBuffer,
        nOutBufferSize,
        lpBytesReturned,
        NULL
    );
    return bResult;
}

int main(int argc, char* argv[]) {
    HANDLE hDevice = CreateFile(L"\\\\.\\cartidriver", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("Error: Could not open device - %d\n", GetLastError());
        return 1;
    }

    printf("Test\n");
    UserData data;
    data.target_pid = 0x24F0;
    data.target_address = 0x7FF7EF73B000;
    data.buffer_address = (PBYTE)malloc(64);
    data.Size = 64;

    // 初始化目标进程
    DWORD bytesReturned;
    // 读取内存
    if (!SendIoControlCode(hDevice, read_code, &data, sizeof(data), &data, sizeof(data), &bytesReturned)) {
        printf("Error: read_code failed - %d\n", GetLastError());
        CloseHandle(hDevice);
        free(data.buffer_address);
        return 1;
    }

    printf("Memory content before write: ");
    for (SIZE_T i = 0; i < data.Size; i++) {
        printf("%02X ", data.buffer_address[i]);
    }
    printf("\n");

    // 准备写入数据
    memset(data.buffer_address, 'A', 64); // 将缓冲区填充为64个 'A' 字符

    // 写入内存
    if (!SendIoControlCode(hDevice, write_code, &data, sizeof(data), &data, sizeof(data), &bytesReturned)) {
        printf("Error: write_code failed - %d\n", GetLastError());
        CloseHandle(hDevice);
        free(data.buffer_address);
        return 1;
    }

    printf("Read After Write:\n");
    // 再次读取内存
    if (!SendIoControlCode(hDevice, read_code, &data, sizeof(data), &data, sizeof(data), &bytesReturned)) {
        printf("Error: read_code failed - %d\n", GetLastError());
        CloseHandle(hDevice);
        free(data.buffer_address);
        return 1;
    }

    printf("Memory content after write: ");
    for (SIZE_T i = 0; i < data.Size; i++) {
        printf("%02X ", data.buffer_address[i]);
    }
    printf("\n");

    // 清理
    CloseHandle(hDevice);
    free(data.buffer_address);

    return 0;
}
