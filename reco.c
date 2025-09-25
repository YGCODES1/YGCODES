#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winioctl.h>

#define MAX_DISKS 10
#define MAX_FILES 5000
#define SECTOR_SIZE 512
#define BUFFER_SIZE 4096
#define CLUSTER_SIZE 4096
#define MFT_RECORD_SIZE 1024
#define MFT_BUFFER_SIZE (1024ULL * 1024)  // 1MB buffer
#undef min
#define min(a,b) ((a) < (b) ? (a) : (b))

#pragma pack(push, 1)

// NTFS Boot Sector
typedef struct {
    BYTE jump[3];
    char oem[8];
    WORD bytesPerSector;
    BYTE sectorsPerCluster;
    BYTE reserved[7];
    BYTE media;
    WORD reserved2;
    WORD sectorsPerTrack;
    WORD numberOfHeads;
    DWORD hiddenSectors;
    DWORD reserved3;
    ULONGLONG totalSectors;
    ULONGLONG mftClusterNumber;
    ULONGLONG mftMirrorClusterNumber;
    DWORD clustersPerMftRecord;  // Negative for bytes
    ULONGLONG indexBufferSize;
    BYTE reserved4[428];
    WORD bootSignature;
} NTFS_BOOT_SECTOR;

// NTFS MFT Entry Header
typedef struct {
    DWORD signature;        // "FILE"
    WORD usa_offset;
    WORD usa_count;
    ULONGLONG lsn;
    WORD sequence_number;
    WORD link_count;
    WORD attrs_offset;
    WORD flags;
    DWORD used_size;
    DWORD alloc_size;
    ULONGLONG base_ref;
    WORD next_attr_id;
    DWORD mft_record;
    WORD padding;
} MFT_ENTRY_HEADER;

// NTFS Attribute Header
typedef struct {
    DWORD type;
    DWORD length;
    BYTE non_resident;
    BYTE name_length;
    WORD name_offset;
    WORD flags;
    WORD instance;
    union {
        struct {
            DWORD value_length;
            WORD value_offset;
        } resident;
        struct {
            ULONGLONG lowest_vcn;
            ULONGLONG highest_vcn;
            WORD data_run_offset;
            WORD compression_unit;
            ULONGLONG alloc_size;
            ULONGLONG data_size;
            ULONGLONG valid_size;
            ULONGLONG total_size;
        } non_res;
    };
} ATTRIBUTE_HEADER;

// File Name Attribute
typedef struct {
    ULONGLONG parent_ref;
    ULARGE_INTEGER creation_time;
    ULARGE_INTEGER change_time;
    ULARGE_INTEGER last_write_time;
    ULARGE_INTEGER last_access_time;
    ULONGLONG alloc_size;
    ULONGLONG data_size;
    DWORD file_attrs;
    DWORD name_len;
    WORD name_type;
    WCHAR name[1];  // Variable length
} FILE_NAME_ATTR;

#pragma pack(pop)

typedef struct {
    char name[MAX_PATH];
    char path[5];
    DWORD serialNumber;
    ULONGLONG totalSize;
    ULONGLONG freeSize;
    char fileSystem[10];
} DiskInfo;

typedef struct {
    char name[MAX_PATH];
    ULONGLONG size;
    BOOL isDeleted;
    ULONGLONG startCluster;
    ULONGLONG clusterCount;
    char fileType[10];
    ULONGLONG mftIndex;
} FileInfo;

// Fonksiyon prototipleri
int listDisks(DiskInfo disks[]);
int selectDisk(DiskInfo disks[], int diskCount);
const char* detectFileType(BYTE* buffer, DWORD size);
BOOL readBootSector(HANDLE hDrive, NTFS_BOOT_SECTOR* boot);
void applyFixup(BYTE* record);
void parseDataRuns(BYTE* runList, DWORD attrLength, ULONGLONG bytesPerCluster, FileInfo* fileInfo);
int scanMFTForDeleted(char driveLetter, FileInfo files[], ULONGLONG bytesPerCluster, ULONGLONG mftStart, ULONGLONG mftSize);
BOOL recoverDeletedFile(char driveLetter, FileInfo file, const char* outputPath, HANDLE hDrive, ULONGLONG bytesPerCluster, BYTE* mftRecord);
BOOL recoverFile(char driveLetter, FileInfo file, const char* outputPath);
void deepScan(char driveLetter, const char* outputPath);
ULONGLONG getMFTSize(HANDLE hDrive, ULONGLONG bytesPerCluster);

// MFT boyutunu al ($MFT kaydından)
ULONGLONG getMFTSize(HANDLE hDrive, ULONGLONG bytesPerCluster) {
    BYTE mftRecord[MFT_RECORD_SIZE];
    LARGE_INTEGER offset = {0}; // $MFT ilk kayıttır
    DWORD bytesRead;
    SetFilePointerEx(hDrive, offset, NULL, FILE_BEGIN);
    if (!ReadFile(hDrive, mftRecord, MFT_RECORD_SIZE, &bytesRead, NULL) || bytesRead != MFT_RECORD_SIZE) {
        printf("MFT kaydi okuma hatasi: %d\n", GetLastError());
        return 10ULL * 1024 * 1024 * 1024; // Varsayılan 10GB
    }

    MFT_ENTRY_HEADER* header = (MFT_ENTRY_HEADER*)mftRecord;
    if (header->signature != 0x454C4946) {
        printf("Gecersiz $MFT kaydi!\n");
        return 10ULL * 1024 * 1024 * 1024;
    }

    BYTE* attrPtr = mftRecord + header->attrs_offset;
    while (attrPtr < mftRecord + header->used_size && attrPtr < mftRecord + MFT_RECORD_SIZE) {
        ATTRIBUTE_HEADER* attr = (ATTRIBUTE_HEADER*)attrPtr;
        if (attr->type == 0xFFFFFFFF || attr->length == 0 || attr->length > MFT_RECORD_SIZE - (attrPtr - mftRecord)) break;
        if (attr->type == 0x80 && attr->non_resident) { // $DATA
            return attr->non_res.data_size;
        }
        attrPtr += attr->length;
    }
    printf("MFT boyutu bulunamadi, varsayilan kullaniliyor!\n");
    return 10ULL * 1024 * 1024 * 1024;
}

// Boot sector oku
BOOL readBootSector(HANDLE hDrive, NTFS_BOOT_SECTOR* boot) {
    BYTE sector[SECTOR_SIZE];
    DWORD bytesRead;
    if (!ReadFile(hDrive, sector, SECTOR_SIZE, &bytesRead, NULL) || bytesRead != SECTOR_SIZE) {
        printf("Boot sektor okuma hatasi: %d\n", GetLastError());
        return FALSE;
    }
    memcpy(boot, sector, sizeof(NTFS_BOOT_SECTOR));
    if (memcmp(boot->oem, "NTFS    ", 8) != 0) {
        printf("Disk NTFS degil!\n");
        return FALSE;
    }
    return TRUE;
}

// MFT record fixup uygula (USA)
void applyFixup(BYTE* record) {
    MFT_ENTRY_HEADER* header = (MFT_ENTRY_HEADER*)record;
    if (header->usa_offset == 0 || header->usa_count == 0) return;
    if (header->usa_offset + header->usa_count * sizeof(WORD) > MFT_RECORD_SIZE) return;
    WORD* usa = (WORD*)(record + header->usa_offset);
    for (int i = 0; i < header->usa_count - 1; i++) {
        if (SECTOR_SIZE * (i + 1) - 2 > MFT_RECORD_SIZE) break;
        WORD fixup = usa[i + 1];
        WORD* sectorEnd = (WORD*)(record + SECTOR_SIZE * (i + 1) - 2);
        *sectorEnd = fixup;
    }
}

// Data run parse et
void parseDataRuns(BYTE* runList, DWORD attrLength, ULONGLONG bytesPerCluster, FileInfo* fileInfo) {
    ULONGLONG currentLcn = 0;
    ULONGLONG totalClusters = 0;
    BYTE* ptr = runList;
    BYTE* end = runList + attrLength;

    while (*ptr != 0 && ptr < end) {
        BYTE runHeader = *ptr++;
        BYTE lengthBytes = runHeader & 0x0F;
        BYTE offsetBytes = (runHeader >> 4) & 0x0F;

        ULONGLONG length = 0;
        if (lengthBytes > 0 && ptr + lengthBytes <= end) {
            memcpy(&length, ptr, lengthBytes);
            ptr += lengthBytes;
        } else {
            break;
        }

        LONGLONG offset = 0;
        if (offsetBytes > 0 && ptr + offsetBytes <= end) {
            memcpy(&offset, ptr, offsetBytes);
            ptr += offsetBytes;
        } else {
            break;
        }

        currentLcn += offset;
        if (length > 0) {
            fileInfo->startCluster = currentLcn;
            totalClusters += length;
        }
    }

    fileInfo->clusterCount = totalClusters;
}

// Silinmiş dosyaları MFT'den tara (NTFS only)
int scanMFTForDeleted(char driveLetter, FileInfo files[], ULONGLONG bytesPerCluster, ULONGLONG mftStart, ULONGLONG mftSize) {
    char physicalDrive[20];
    sprintf(physicalDrive, "\\\\.\\%c:", driveLetter);
    HANDLE hDrive = CreateFileA(physicalDrive, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDrive == INVALID_HANDLE_VALUE) {
        printf("Disk acilamadi: %d (Admin yetkisi kontrol edin)\n", GetLastError());
        return 0;
    }

    printf("MFT tarama basliyor, MFT boyutu: %llu bytes...\n", mftSize);
    BYTE* mftBuffer = malloc(MFT_BUFFER_SIZE);
    if (!mftBuffer) {
        printf("Bellek ayirma hatasi!\n");
        CloseHandle(hDrive);
        return 0;
    }

    int fileCount = 0;
    LARGE_INTEGER offset;
    offset.QuadPart = mftStart * bytesPerCluster;
    ULONGLONG totalBytesRead = 0;

    while (totalBytesRead < mftSize && fileCount < MAX_FILES) {
        SetFilePointerEx(hDrive, offset, NULL, FILE_BEGIN);
        DWORD bytesRead;
        if (!ReadFile(hDrive, mftBuffer, MFT_BUFFER_SIZE, &bytesRead, NULL) || bytesRead == 0) {
            printf("MFT okuma hatasi: %d\n", GetLastError());
            break;
        }

        printf("MFT parcasi okundu: %u bytes\n", bytesRead);
        for (DWORD i = 0; i < bytesRead && fileCount < MAX_FILES; i += MFT_RECORD_SIZE) {
            if (totalBytesRead + i + MFT_RECORD_SIZE > totalBytesRead + bytesRead) break;
            if (totalBytesRead + i >= mftSize) break;
            if (i % (100 * MFT_RECORD_SIZE) == 0) {
                printf("Ilerleme: %llu/%llu bytes tarandi\n", totalBytesRead + i, mftSize);
            }

            BYTE* record = mftBuffer + i;
            MFT_ENTRY_HEADER* header = (MFT_ENTRY_HEADER*)record;
            applyFixup(record);

            if (header->signature != 0x454C4946 /* "FILE" */) {
                printf("Gecersiz MFT kaydi atlandi: offset %llu\n", totalBytesRead + i);
                continue;
            }
            if (header->flags & 1) continue; // In use, atla

            printf("Silinmis dosya kaydi bulundu: offset %llu\n", totalBytesRead + i);
            BYTE* attrPtr = record + header->attrs_offset;
            if (attrPtr >= record + MFT_RECORD_SIZE) {
                printf("Hatali attrs_offset: %u, atlandi\n", header->attrs_offset);
                continue;
            }

            FileInfo* currentFile = &files[fileCount];
            currentFile->mftIndex = (totalBytesRead + i) / MFT_RECORD_SIZE;
            sprintf(currentFile->name, "Unknown_%llu", currentFile->mftIndex); // Varsayılan ad
            currentFile->isDeleted = TRUE;
            strcpy(currentFile->fileType, "UNKNOWN");

            while (attrPtr < record + header->used_size && attrPtr < record + MFT_RECORD_SIZE) {
                ATTRIBUTE_HEADER* attr = (ATTRIBUTE_HEADER*)attrPtr;
                if (attr->type == 0xFFFFFFFF || attr->length == 0 || attr->length > MFT_RECORD_SIZE - (attrPtr - record)) {
                    printf("Hatali attribute atlandi: type %u, uzunluk %u\n", attr->type, attr->length);
                    break;
                }

                if (attr->type == 0x30 /* $FILE_NAME */) {
                    if (attr->resident.value_offset > attr->length) {
                        printf("Hatali value_offset: %u, atlandi\n", attr->resident.value_offset);
                        continue;
                    }
                    FILE_NAME_ATTR* fn = (FILE_NAME_ATTR*)(attrPtr + attr->resident.value_offset);
                    if (fn->name_len > 0) {
                        int nameLen = min(fn->name_len, MAX_PATH - 1);
                        WideCharToMultiByte(CP_UTF8, 0, fn->name, nameLen, currentFile->name, MAX_PATH, NULL, NULL);
                        currentFile->name[nameLen] = 0;
                        currentFile->size = fn->data_size;
                        printf("Dosya adi: %s, boyutu: %llu bytes\n", currentFile->name, currentFile->size);
                    }
                }
                else if (attr->type == 0x80 /* $DATA */ && attr->non_resident) {
                    if (attr->non_res.data_run_offset < attr->length) {
                        parseDataRuns(attrPtr + attr->non_res.data_run_offset, attr->length - attr->non_res.data_run_offset, bytesPerCluster, currentFile);
                    }
                }
                attrPtr += attr->length;
                if (attrPtr >= record + MFT_RECORD_SIZE) {
                    printf("attrPtr sinir asimi, kiriliyor\n");
                    break;
                }
            }
            if (currentFile->name[0] && currentFile->size > 0) {
                fileCount++;
                printf("Dosya eklendi: %s\n", currentFile->name);
            }
        }

        totalBytesRead += bytesRead;
        offset.QuadPart += bytesRead;
        if (bytesRead < MFT_BUFFER_SIZE) break;
    }

    free(mftBuffer);
    CloseHandle(hDrive);
    printf("MFT tarama tamamlandi: %d dosya bulundu\n", fileCount);
    return fileCount;
}

// Silinmiş dosyayı kurtar
BOOL recoverDeletedFile(char driveLetter, FileInfo file, const char* outputPath, HANDLE hDrive, ULONGLONG bytesPerCluster, BYTE* mftRecord) {
    BYTE* attrPtr = mftRecord + ((MFT_ENTRY_HEADER*)mftRecord)->attrs_offset;
    ULONGLONG totalClusters = 0;
    ULONGLONG totalSize = 0;

    while (attrPtr < mftRecord + MFT_RECORD_SIZE) {
        ATTRIBUTE_HEADER* attr = (ATTRIBUTE_HEADER*)attrPtr;
        if (attr->type == 0x80 && attr->non_resident) {
            if (attr->non_res.data_run_offset < attr->length) {
                parseDataRuns(attrPtr + attr->non_res.data_run_offset, attr->length - attr->non_res.data_run_offset, bytesPerCluster, &file);
                totalClusters = file.clusterCount;
                totalSize = attr->non_res.data_size;
            }
            break;
        }
        attrPtr += attr->length;
        if (attrPtr >= mftRecord + MFT_RECORD_SIZE) break;
    }

    if (!totalClusters || totalSize == 0) {
        printf("Dosya icin veri bulunamadi: %s\n", file.name);
        return FALSE;
    }

    char destPath[MAX_PATH];
    sprintf(destPath, "%s\\REC_%s", outputPath, file.name);
    HANDLE hOut = CreateFileA(destPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOut == INVALID_HANDLE_VALUE) {
        printf("Cikti dosyasi olusturulamadi: %s (Hata: %d)\n", destPath, GetLastError());
        return FALSE;
    }

    BYTE* clusterBuf = malloc(bytesPerCluster);
    if (!clusterBuf) {
        printf("Bellek ayirma hatasi!\n");
        CloseHandle(hOut);
        return FALSE;
    }

    ULONGLONG bytesWritten = 0;
    for (ULONGLONG c = 0; c < totalClusters && bytesWritten < totalSize; c++) {
        LARGE_INTEGER clOffset;
        clOffset.QuadPart = (file.startCluster + c) * bytesPerCluster;
        SetFilePointerEx(hDrive, clOffset, NULL, FILE_BEGIN);
        DWORD bytesRead;
        if (ReadFile(hDrive, clusterBuf, bytesPerCluster, &bytesRead, NULL) && bytesRead > 0) {
            DWORD written;
            if (WriteFile(hOut, clusterBuf, min(bytesRead, totalSize - bytesWritten), &written, NULL)) {
                bytesWritten += written;
            } else {
                printf("Yazma hatasi: %s (Hata: %d)\n", file.name, GetLastError());
                break;
            }
        } else {
            printf("Cluster okuma hatasi: %s (Hata: %d)\n", file.name, GetLastError());
        }
    }

    free(clusterBuf);
    CloseHandle(hOut);

    // Dosya boyut doğrulaması
    HANDLE hVerify = CreateFileA(destPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hVerify != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER fileSize;
        if (GetFileSizeEx(hVerify, &fileSize) && fileSize.QuadPart == totalSize) {
            printf("Kurtarildi: %s (%llu bytes, dogrulandi)\n", destPath, bytesWritten);
            CloseHandle(hVerify);
            return TRUE;
        } else {
            printf("Kurtarma basarisiz: %s (Boyut eslesmedi, beklenen: %llu, yazilan: %llu)\n", destPath, totalSize, bytesWritten);
            CloseHandle(hVerify);
            return FALSE;
        }
    } else {
        printf("Kurtarma basarisiz: %s (Dosya dogrulanamadi, Hata: %d)\n", destPath, GetLastError());
        return FALSE;
    }
}

// Diskleri listele
int listDisks(DiskInfo disks[]) {
    int count = 0;
    char driveLetters[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    
    for (int i = 0; i < 26; i++) {
        char rootPath[10] = {driveLetters[i], ':', '\\', '\0'};
        UINT type = GetDriveTypeA(rootPath);
        
        if (type == DRIVE_FIXED || type == DRIVE_REMOVABLE) {
            char volumeName[MAX_PATH];
            DWORD serialNumber;
            DWORD maxComponentLength;
            DWORD fileSystemFlags;
            char fileSystemName[10];
            
            if (GetVolumeInformationA(rootPath, volumeName, MAX_PATH, &serialNumber, 
                                    &maxComponentLength, &fileSystemFlags, 
                                    fileSystemName, sizeof(fileSystemName))) {
                
                ULARGE_INTEGER freeBytes, totalBytes, totalFreeBytes;
                
                if (GetDiskFreeSpaceExA(rootPath, &freeBytes, &totalBytes, &totalFreeBytes)) {
                    strncpy(disks[count].name, volumeName, MAX_PATH - 1);
                    disks[count].name[MAX_PATH - 1] = 0;
                    sprintf(disks[count].path, "%c:", driveLetters[i]);
                    disks[count].serialNumber = serialNumber;
                    disks[count].totalSize = totalBytes.QuadPart;
                    disks[count].freeSize = freeBytes.QuadPart;
                    strncpy(disks[count].fileSystem, fileSystemName, 9);
                    disks[count].fileSystem[9] = 0;
                    count++;
                    
                    if (count >= MAX_DISKS) break;
                }
            }
        }
    }
    
    return count;
}

// Disk seç
int selectDisk(DiskInfo disks[], int diskCount) {
    printf("\nMevcut Diskler:\n");
    printf("No\tDisk\tDosya Sistemi\tIsim\t\tBoyut\t\tBos Alan\n");
    printf("----------------------------------------------------------------\n");
    
    for (int i = 0; i < diskCount; i++) {
        printf("%d\t%s\t%s\t\t%s\t%.2f GB\t%.2f GB\n", 
               i + 1, 
               disks[i].path, 
               disks[i].fileSystem,
               disks[i].name,
               (double)disks[i].totalSize / (1024 * 1024 * 1024),
               (double)disks[i].freeSize / (1024 * 1024 * 1024));
    }
    
    int selection;
    printf("\nKurtarma yapilacak disk numarasini secin (1-%d): ", diskCount);
    scanf("%d", &selection);
    
    if (selection < 1 || selection > diskCount) {
        printf("Gecersiz secim!\n");
        return -1;
    }
    
    return selection - 1;
}

// Dosya tipi tespit
const char* detectFileType(BYTE* buffer, DWORD size) {
    if (size < 4) return "UNKNOWN";
    
    if (buffer[0] == 0xFF && buffer[1] == 0xD8 && buffer[2] == 0xFF) return "JPEG";
    if (buffer[0] == 0x89 && buffer[1] == 0x50 && buffer[2] == 0x4E && buffer[3] == 0x47) return "PNG";
    if (buffer[0] == 0x25 && buffer[1] == 0x50 && buffer[2] == 0x44 && buffer[3] == 0x46) return "PDF";
    if (buffer[0] == 0x50 && buffer[1] == 0x4B && buffer[2] == 0x03 && buffer[3] == 0x04) return "ZIP";
    if (buffer[0] == 0x52 && buffer[1] == 0x61 && buffer[2] == 0x72 && buffer[3] == 0x21) return "RAR";
    if (buffer[0] == 0x47 && buffer[1] == 0x49 && buffer[2] == 0x46 && buffer[3] == 0x38) return "GIF";
    if (buffer[0] == 0x49 && buffer[1] == 0x44 && buffer[2] == 0x33) return "MP3";
    
    return "UNKNOWN";
}

// Dosya kurtar
BOOL recoverFile(char driveLetter, FileInfo file, const char* outputPath) {
    if (!file.isDeleted) {
        char sourcePath[MAX_PATH];
        sprintf(sourcePath, "%c:\\%s", driveLetter, file.name);
        char destinationPath[MAX_PATH];
        sprintf(destinationPath, "%s\\%s", outputPath, file.name);
        if (CopyFileA(sourcePath, destinationPath, FALSE)) {
            printf("Kurtarildi: %s\n", destinationPath);
            return TRUE;
        }
        printf("Kurtarma basarisiz: %s (Hata: %d)\n", file.name, GetLastError());
        return FALSE;
    } else {
        char physicalDrive[20];
        sprintf(physicalDrive, "\\\\.\\%c:", driveLetter);
        HANDLE hDrive = CreateFileA(physicalDrive, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (hDrive == INVALID_HANDLE_VALUE) {
            printf("Disk acilamadi: %d (Admin yetkisi kontrol edin)\n", GetLastError());
            return FALSE;
        }

        NTFS_BOOT_SECTOR boot;
        if (!readBootSector(hDrive, &boot)) {
            printf("Boot sektor hatasi, NTFS degil!\n");
            CloseHandle(hDrive);
            return FALSE;
        }
        ULONGLONG bytesPerCluster = boot.bytesPerSector * boot.sectorsPerCluster;
        ULONGLONG mftStart = boot.mftClusterNumber;

        BYTE mftRecord[MFT_RECORD_SIZE];
        LARGE_INTEGER mftOffset;
        mftOffset.QuadPart = mftStart * bytesPerCluster + file.mftIndex * MFT_RECORD_SIZE;
        SetFilePointerEx(hDrive, mftOffset, NULL, FILE_BEGIN);
        DWORD bytesRead;
        if (!ReadFile(hDrive, mftRecord, MFT_RECORD_SIZE, &bytesRead, NULL) || bytesRead != MFT_RECORD_SIZE) {
            printf("MFT kaydi okuma hatasi: %s (Hata: %d)\n", file.name, GetLastError());
            CloseHandle(hDrive);
            return FALSE;
        }

        BOOL success = recoverDeletedFile(driveLetter, file, outputPath, hDrive, bytesPerCluster, mftRecord);
        CloseHandle(hDrive);
        return success;
    }
}

// Derin tarama (imza tabanlı)
void deepScan(char driveLetter, const char* outputPath) {
    printf("Derin tarama baslatiliyor...\n");
    
    char physicalDrive[20];
    sprintf(physicalDrive, "\\\\.\\%c:", driveLetter);
    
    HANDLE hDrive = CreateFileA(physicalDrive, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDrive == INVALID_HANDLE_VALUE) {
        printf("Disk acilamadi: %d (Admin yetkisi kontrol edin)\n", GetLastError());
        return;
    }

    LARGE_INTEGER diskSize;
    GetFileSizeEx(hDrive, &diskSize);
    
    BYTE buffer[BUFFER_SIZE];
    DWORD bytesRead;
    LARGE_INTEGER offset = {0};
    int fileCount = 0;
    
    printf("Disk boyutu: %.2f GB\n", (double)diskSize.QuadPart / (1024 * 1024 * 1024));
    
    for (LONGLONG i = 0; i < diskSize.QuadPart; i += BUFFER_SIZE) {
        offset.QuadPart = i;
        SetFilePointerEx(hDrive, offset, NULL, FILE_BEGIN);
        if (!ReadFile(hDrive, buffer, BUFFER_SIZE, &bytesRead, NULL)) {
            printf("Disk okuma hatasi: %d\n", GetLastError());
            continue;
        }
        
        const char* fileType = detectFileType(buffer, bytesRead);
        if (strcmp(fileType, "UNKNOWN") != 0) {
            printf("Bulundu: ofset %llu, tip: %s\n", i, fileType);
            char outputFile[MAX_PATH];
            sprintf(outputFile, "%s\\recovered_%llu.%s", outputPath, i, fileType);
            
            HANDLE hOutput = CreateFileA(outputFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hOutput != INVALID_HANDLE_VALUE) {
                DWORD bytesWritten;
                WriteFile(hOutput, buffer, bytesRead, &bytesWritten, NULL);
                CloseHandle(hOutput);
                fileCount++;
                printf("Kurtarildi: %s\n", outputFile);
            } else {
                printf("Cikti dosyasi olusturulamadi: %s (Hata: %d)\n", outputFile, GetLastError());
            }
        }
        if (i % (100 * BUFFER_SIZE) == 0) {
            printf("Ilerleme: %.2f%%\n", (double)i * 100 / diskSize.QuadPart);
        }
    }
    
    CloseHandle(hDrive);
    printf("Derin tarama tamamlandi. %d dosya kurtarildi.\n", fileCount);
}

// Ana program
int main() {
    printf("=== VERI KURTARMA PROGRAMI (NTFS MFT Destekli) ===\n");
    printf("Admin yetkisiyle calistirin!\n");
    
    DiskInfo disks[MAX_DISKS];
    int diskCount = listDisks(disks);
    
    if (diskCount == 0) {
        printf("Herhangi bir disk bulunamadi!\n");
        return 1;
    }
    
    int selectedDiskIndex = selectDisk(disks, diskCount);
    if (selectedDiskIndex == -1) {
        printf("Disk secimi basarisiz!\n");
        return 1;
    }
    
    DiskInfo selectedDisk = disks[selectedDiskIndex];
    if (strcmp(selectedDisk.fileSystem, "NTFS") != 0) {
        printf("Sadece NTFS destekleniyor! Disk: %s (%s)\n", selectedDisk.path, selectedDisk.fileSystem);
        return 1;
    }
    
    printf("\nSecilen disk: %s (%s - %s)\n", selectedDisk.path, selectedDisk.name, selectedDisk.fileSystem);
    
    char physicalDrive[20];
    sprintf(physicalDrive, "\\\\.\\%c:", selectedDisk.path[0]);
    HANDLE hDrive = CreateFileA(physicalDrive, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDrive == INVALID_HANDLE_VALUE) {
        printf("Disk acilamadi: %d (Admin yetkisi kontrol edin)\n", GetLastError());
        return 1;
    }

    printf("Boot sektor okunuyor...\n");
    NTFS_BOOT_SECTOR boot;
    if (!readBootSector(hDrive, &boot)) {
        printf("Boot sektor hatasi, NTFS degil!\n");
        CloseHandle(hDrive);
        return 1;
    }
    ULONGLONG bytesPerCluster = boot.bytesPerSector * boot.sectorsPerCluster;
    ULONGLONG mftStart = boot.mftClusterNumber;
    ULONGLONG mftSize = getMFTSize(hDrive, bytesPerCluster);
    CloseHandle(hDrive);

    printf("MFT taramasi basliyor...\n");
    FileInfo files[MAX_FILES];
    memset(files, 0, sizeof(files));
    int fileCount = scanMFTForDeleted(selectedDisk.path[0], files, bytesPerCluster, mftStart, mftSize);
    
    printf("MFT tarama bitti, dosya listesi hazirlaniyor...\n");
    char outputPath[MAX_PATH];
    printf("Kurtarilan dosyalarin kaydedilecegi klasoru girin: ");
    if (scanf("%s", outputPath) != 1) {
        printf("Gecersiz klasor girisi!\n");
        return 1;
    }
    CreateDirectoryA(outputPath, NULL);

    if (fileCount > 0) {
        printf("\nBulunan silinmis dosyalar (%d adet):\n", fileCount);
        printf("No\tIsim\t\tBoyut\tTip\n");
        printf("----------------------------------------\n");
        
        for (int i = 0; i < fileCount; i++) {
            printf("%d\t%s\t%llu KB\t%s\n", 
                   i + 1, files[i].name, files[i].size / 1024, files[i].fileType);
        }

        printf("\nTum silinmis dosyalar otomatik olarak kurtariliyor...\n");
        int successCount = 0;
        for (int i = 0; i < fileCount; i++) {
            if (recoverFile(selectedDisk.path[0], files[i], outputPath)) {
                successCount++;
            }
        }
        printf("\nToplam %d dosyadan %d tanesi kurtarildi.\n", fileCount, successCount);
    } else {
        printf("Silinmis dosya bulunamadi. Derin tarama yapmak ister misiniz? (e/h): ");
        char choice;
        scanf(" %c", &choice);
        if (choice == 'e' || choice == 'E') {
            printf("Derin tarama secildi...\n");
            deepScan(selectedDisk.path[0], outputPath);
        }
    }
    
    printf("\nProgram sonlandi. Cikis icin bir tusa basin...\n");
    while (getchar() != '\n');
    getchar();
    
    return 0;
}