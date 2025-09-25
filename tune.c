#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <time.h>

#define MAX_DISKS 26
#define SECTOR_SIZE 512

#pragma pack(push, 1)
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
    DWORD clustersPerMftRecord;
    ULONGLONG indexBufferSize;
    BYTE reserved4[428];
    WORD bootSignature;
} NTFS_BOOT_SECTOR;
#pragma pack(pop)

typedef struct {
    char path[10];
    char name[256];
    double sizeGB;
    char fileSystem[10];
} DiskInfo;

DiskInfo disks[MAX_DISKS];
int diskCount = 0;
FILE* logFile = NULL;

void AddLog(const char* msg) {
    char timeStr[256];
    time_t now = time(NULL);
    struct tm* t = localtime(&now);
    snprintf(timeStr, 256, "[%04d-%02d-%02d %02d:%02d:%02d] %s",
             t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
             t->tm_hour, t->tm_min, t->tm_sec, msg);
    printf("%s\n", timeStr);
    if (logFile) {
        fprintf(logFile, "%s\n", timeStr);
        fflush(logFile);
    }
}

BOOL WriteNTFSBootSector(HANDLE hDrive, ULONGLONG totalSectors) {
    BYTE sector[SECTOR_SIZE] = {0};
    DWORD bytesWritten;
    NTFS_BOOT_SECTOR boot = {0};
    boot.jump[0] = 0xEB;
    boot.jump[1] = 0x52;
    boot.jump[2] = 0x90;
    memcpy(boot.oem, "NTFS    ", 8);
    boot.bytesPerSector = SECTOR_SIZE;
    boot.sectorsPerCluster = 8;
    boot.media = 0xF8;
    boot.sectorsPerTrack = 63;
    boot.numberOfHeads = 255;
    boot.totalSectors = totalSectors;
    boot.mftClusterNumber = 786432;
    boot.mftMirrorClusterNumber = 2;
    boot.clustersPerMftRecord = 1;
    boot.bootSignature = 0xAA55;
    memcpy(sector, &boot, sizeof(NTFS_BOOT_SECTOR));

    LARGE_INTEGER offset = {0};
    SetFilePointerEx(hDrive, offset, NULL, FILE_BEGIN);
    if (!WriteFile(hDrive, sector, SECTOR_SIZE, &bytesWritten, NULL) || bytesWritten != SECTOR_SIZE) {
        AddLog("Boot sektor yazilamadi!");
        return FALSE;
    }
    return TRUE;
}

BOOL FormatDisk(HANDLE hDrive) {
    DISK_GEOMETRY geom;
    DWORD bytesReturned;
    if (!DeviceIoControl(hDrive, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &geom, sizeof(geom), &bytesReturned, NULL)) {
        AddLog("Disk geometrisi alinamadi!");
        return FALSE;
    }
    ULONGLONG totalSectors = geom.Cylinders.QuadPart * geom.TracksPerCylinder * geom.SectorsPerTrack;
    return WriteNTFSBootSector(hDrive, totalSectors);
}

void ListDrives() {
    DWORD drives = GetLogicalDrives();
    diskCount = 0;
    for (int i = 0; i < 26; i++) {
        if (drives & (1 << i)) {
            char driveLetter = 'A' + i;
            char volPath[10];
            snprintf(volPath, 10, "\\\\.\\%c:", driveLetter);
            HANDLE hDrive = CreateFileA(volPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
            if (hDrive != INVALID_HANDLE_VALUE) {
                char volName[256];
                char fileSystem[10];
                char displayPath[10];
                snprintf(displayPath, 10, "%c:", driveLetter);
                if (GetVolumeInformationA(displayPath, volName, 256, NULL, NULL, NULL, fileSystem, 10)) {
                    strcpy(disks[diskCount].path, volPath);
                    strcpy(disks[diskCount].name, volName[0] ? volName : "Isimsiz");
                    strcpy(disks[diskCount].fileSystem, fileSystem);
                    ULARGE_INTEGER totalBytes;
                    GetDiskFreeSpaceExA(displayPath, NULL, &totalBytes, NULL);
                    disks[diskCount].sizeGB = (double)totalBytes.QuadPart / (1024 * 1024 * 1024);
                    printf("%d: %s (%c:) [%.2f GB, %s]\n", diskCount, disks[diskCount].name,
                           driveLetter, disks[diskCount].sizeGB, disks[diskCount].fileSystem);
                    diskCount++;
                }
                CloseHandle(hDrive);
            }
        }
    }
    if (diskCount == 0) {
        AddLog("Surucu bulunamadi!");
    } else {
        AddLog("Suruculer listelendi");
    }
}

int main() {
    CreateDirectoryA("C:\\Formatter", NULL);
    logFile = fopen("C:\\Formatter\\log.txt", "a");
    if (!logFile) {
        printf("Hata: Log dosyasi acilamadi!\n");
        return 1;
    }

    HANDLE hDrive = INVALID_HANDLE_VALUE;
    int choice;
    char confirm;

    while (1) {
        printf("\n=== Disk Bicimlendirme ===\n");
        ListDrives();
        if (diskCount == 0) {
            printf("Programdan cikiliyor...\n");
            fclose(logFile);
            return 1;
        }

        printf("\nSurucu sec (0-%d, cikis: -1): ", diskCount - 1);
        if (scanf("%d", &choice) != 1 || choice < -1 || choice >= diskCount) {
            AddLog("Gecersiz surucu secimi!");
            printf("Hata: Gecersiz secim!\n");
            while (getchar() != '\n');
            continue;
        }
        if (choice == -1) {
            AddLog("Programdan cikiliyor");
            printf("Cikiliyor...\n");
            fclose(logFile);
            return 0;
        }

        printf("%s (%c:) surucusu NTFS ile hizli bicimlendirilecek. Emin misiniz? [E/H]: ",
               disks[choice].name, disks[choice].path[4]);
        AddLog("Bicimlendirme onay bekliyor");
        while (getchar() != '\n');
        confirm = getchar();
        if (confirm != 'E' && confirm != 'e') {
            AddLog("Bicimlendirme iptal edildi");
            printf("Iptal edildi.\n");
            while (getchar() != '\n');
            continue;
        }

        hDrive = CreateFileA(disks[choice].path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (hDrive == INVALID_HANDLE_VALUE) {
            AddLog("Surucu acilamadi! Admin yetkisi veya kilit kontrol edin.");
            printf("Hata: Surucu acilamadi! Yonetici yetkisi veya kilit kontrol edin.\n");
            while (getchar() != '\n');
            continue;
        }

        if (FormatDisk(hDrive)) {
            AddLog("Bicimlendirme tamamlandi!");
            printf("Bicimlendirme tamamlandi!\n");
        } else {
            AddLog("Bicimlendirme basarisiz!");
            printf("Hata: Bicimlendirme basarisiz!\n");
        }
        CloseHandle(hDrive);
        hDrive = INVALID_HANDLE_VALUE;
        while (getchar() != '\n');
    }

    fclose(logFile);
    return 0;
}