//
//  ViewController.m
//  Rollectra
//
//  Created by pwn20wnd on 8/29/18.
//  Copyright © 2018 Pwn20wnd. All rights reserved.
//

#include <sys/stat.h>
#include <spawn.h>
#include <sys/attr.h>
#include <sys/snapshot.h>
#include <dlfcn.h>
#import "ViewController.h"
#include "common.h"
#ifndef WANT_CYDIA
#include "offsets.h"
#include "sploit.h"
#include "kmem.h"
#endif    /* WANT_CYDIA */
#include "QiLin.h"
#include "iokit.h"

@interface ViewController ()

@end

@implementation ViewController

#ifndef WANT_CYDIA

// https://github.com/JonathanSeals/kernelversionhacker/blob/3dcbf59f316047a34737f393ff946175164bf03f/kernelversionhacker.c#L92

#define IMAGE_OFFSET 0x2000
#define MACHO_HEADER_MAGIC 0xfeedfacf
#define MAX_KASLR_SLIDE 0x21000000
#define KERNEL_SEARCH_ADDRESS_IOS10 0xfffffff007004000

#define ptrSize sizeof(uintptr_t)

static vm_address_t get_kernel_base(mach_port_t tfp0) {
    uint64_t addr = 0;
    addr = KERNEL_SEARCH_ADDRESS_IOS10+MAX_KASLR_SLIDE;
    
    while (1) {
        char *buf;
        mach_msg_type_number_t sz = 0;
        kern_return_t ret = vm_read(tfp0, addr, 0x200, (vm_offset_t*)&buf, &sz);
        
        if (ret) {
            goto next;
        }
        
        if (*((uint32_t *)buf) == MACHO_HEADER_MAGIC) {
            int ret = vm_read(tfp0, addr, 0x1000, (vm_offset_t*)&buf, &sz);
            if (ret != KERN_SUCCESS) {
                printf("Failed vm_read %i\n", ret);
                goto next;
            }
            
            for (uintptr_t i=addr; i < (addr+0x2000); i+=(ptrSize)) {
                mach_msg_type_number_t sz;
                int ret = vm_read(tfp0, i, 0x120, (vm_offset_t*)&buf, &sz);
                
                if (ret != KERN_SUCCESS) {
                    printf("Failed vm_read %i\n", ret);
                    exit(-1);
                }
                if (!strcmp(buf, "__text") && !strcmp(buf+0x10, "__PRELINK_TEXT")) {
                    return addr;
                }
            }
        }
        
    next:
        addr -= 0x200000;
    }
}
#endif    /* WANT_CYDIA */

int sha1_to_str(const unsigned char *hash, int hashlen, char *buf, size_t buflen)
{
    if (buflen < (hashlen*2+1)) {
        return -1;
    }
    
    int i;
    for (i=0; i<hashlen; i++) {
        sprintf(buf+i*2, "%02X", hash[i]);
    }
    buf[i*2] = 0;
    return ERR_SUCCESS;
}

char *copyBootHash(void)
{
    io_registry_entry_t chosen = IORegistryEntryFromPath(kIOMasterPortDefault, "IODeviceTree:/chosen");
    
    if (!MACH_PORT_VALID(chosen)) {
        printf("Unable to get IODeviceTree:/chosen port\n");
        return NULL;
    }
    
    CFDataRef hash = (CFDataRef)IORegistryEntryCreateCFProperty(chosen, CFSTR("boot-manifest-hash"), kCFAllocatorDefault, 0);
    
    IOObjectRelease(chosen);
    
    if (hash == nil) {
        fprintf(stderr, "Unable to read boot-manifest-hash\n");
        return NULL;
    }
    
    if (CFGetTypeID(hash) != CFDataGetTypeID()) {
        fprintf(stderr, "Error hash is not data type\n");
        CFRelease(hash);
        return NULL;
    }
    
    // Make a hex string out of the hash
    
    CFIndex length = CFDataGetLength(hash) * 2 + 1;
    char *manifestHash = (char*)calloc(length, sizeof(char));
    
    int ret = sha1_to_str(CFDataGetBytePtr(hash), (int)CFDataGetLength(hash), manifestHash, length);
    
    CFRelease(hash);
    
    if (ret != ERR_SUCCESS) {
        printf("Unable to generate bootHash string\n");
        free(manifestHash);
        return NULL;
    }
    
    return manifestHash;
}

#define APPLESNAP "com.apple.os.update-"

const char *systemSnapshot(char *bootHash) {
    if (!bootHash) {
        return NULL;
    }
    return [[NSString stringWithFormat:@APPLESNAP @"%s", bootHash] UTF8String];
}

typedef struct val_attrs {
    uint32_t          length;
    attribute_set_t   returned;
    attrreference_t   name_info;
} val_attrs_t;

int snapshot_check(const char *vol, const char *name)
{
    struct attrlist attr_list = { 0 };
    
    attr_list.commonattr = ATTR_BULK_REQUIRED;
    
    char *buf = (char*)calloc(2048, sizeof(char));
    int retcount;
    int fd = open(vol, O_RDONLY, 0);
    while ((retcount = fs_snapshot_list(fd, &attr_list, buf, 2048, 0))>0) {
        char *bufref = buf;
        
        for (int i=0; i<retcount; i++) {
            val_attrs_t *entry = (val_attrs_t *)bufref;
            if (entry->returned.commonattr & ATTR_CMN_NAME) {
                printf("%s\n", (char*)(&entry->name_info) + entry->name_info.attr_dataoffset);
                if (strstr((char*)(&entry->name_info) + entry->name_info.attr_dataoffset, name))
                    return 1;
            }
            bufref += entry->length;
        }
    }
    free(buf);
    close(fd);
    
    if (retcount < 0) {
        perror("fs_snapshot_list");
        return -1;
    }
    
    return 0;
}

// https://github.com/tihmstar/doubleH3lix/blob/4428c660832e98271f5d82f7a9c67e842b814621/doubleH3lix/jailbreak.mm#L645

extern char* const* environ;
int easyPosixSpawn(NSURL *launchPath,NSArray *arguments) {
    NSMutableArray *posixSpawnArguments=[arguments mutableCopy];
    [posixSpawnArguments insertObject:[launchPath lastPathComponent] atIndex:0];
    
    int argc=(int)posixSpawnArguments.count+1;
    printf("Number of posix_spawn arguments: %d\n",argc);
    char **args=(char**)calloc(argc,sizeof(char *));
    
    for (int i=0; i<posixSpawnArguments.count; i++)
        args[i]=(char *)[posixSpawnArguments[i]UTF8String];
    
    printf("File exists at launch path: %d\n",[[NSFileManager defaultManager]fileExistsAtPath:launchPath.path]);
    printf("Executing %s: %s\n",launchPath.path.UTF8String,arguments.description.UTF8String);
    
    posix_spawn_file_actions_t action;
    posix_spawn_file_actions_init(&action);
    
    pid_t pid;
    int status;
    status = posix_spawn(&pid, launchPath.path.UTF8String, &action, NULL, args, environ);
    
    if (status == 0) {
        if (waitpid(pid, &status, 0) != -1) {
            // wait
        }
    }
    
    posix_spawn_file_actions_destroy(&action);
    free(args);
    
    return status;
}

int waitForFile(const char *filename) {
    int rv = 0;
    rv = access(filename, F_OK);
    for (int i = 0; !(i >= 100 || rv == 0); i++) {
        usleep(100000);
        rv = access(filename, F_OK);
    }
    return rv;
}

NSArray *getCleanUpFileList() {
    NSMutableArray *array = nil;
    array = [[NSMutableArray alloc] init];
    // Electra
    [array addObject:@"/electra"];
    [array addObject:@"/usr/lib/libjailbreak.dylib"];
    [array addObject:@"/private/var/mobile/test.txt"];
    [array addObject:@"/.bit_of_fun"];
    [array addObject:@"/.amfid_success"];
    [array addObject:@"/.bootstrapped_electra"];
    // Electra Bootstrap
    [array addObject:@"/Applications/Cydia.app"];
    [array addObject:@"/bin/bash"];
    [array addObject:@"/bin/bunzip2"];
    [array addObject:@"/bin/bzcat"];
    [array addObject:@"/bin/bzip2"];
    [array addObject:@"/bin/bzip2recover"];
    [array addObject:@"/bin/cat"];
    [array addObject:@"/bin/chgrp"];
    [array addObject:@"/bin/chmod"];
    [array addObject:@"/bin/chown"];
    [array addObject:@"/bin/cp"];
    [array addObject:@"/bin/date"];
    [array addObject:@"/bin/dd"];
    [array addObject:@"/bin/dir"];
    [array addObject:@"/bin/echo"];
    [array addObject:@"/bin/egrep"];
    [array addObject:@"/bin/false"];
    [array addObject:@"/bin/fgrep"];
    [array addObject:@"/bin/grep"];
    [array addObject:@"/bin/gtar"];
    [array addObject:@"/bin/gunzip"];
    [array addObject:@"/bin/gzexe"];
    [array addObject:@"/bin/gzip"];
    [array addObject:@"/bin/kill"];
    [array addObject:@"/bin/ln"];
    [array addObject:@"/bin/ls"];
    [array addObject:@"/bin/mkdir"];
    [array addObject:@"/bin/mknod"];
    [array addObject:@"/bin/mktemp"];
    [array addObject:@"/bin/mv"];
    [array addObject:@"/bin/pwd"];
    [array addObject:@"/bin/readlink"];
    [array addObject:@"/bin/rm"];
    [array addObject:@"/bin/rmdir"];
    [array addObject:@"/bin/run-parts"];
    [array addObject:@"/bin/sed"];
    [array addObject:@"/bin/sh"];
    [array addObject:@"/bin/sleep"];
    [array addObject:@"/bin/stty"];
    [array addObject:@"/bin/su"];
    [array addObject:@"/bin/sync"];
    [array addObject:@"/bin/tar"];
    [array addObject:@"/bin/touch"];
    [array addObject:@"/bin/true"];
    [array addObject:@"/bin/uname"];
    [array addObject:@"/bin/uncompress"];
    [array addObject:@"/bin/vdir"];
    [array addObject:@"/bin/zcat"];
    [array addObject:@"/bin/zcmp"];
    [array addObject:@"/bin/zdiff"];
    [array addObject:@"/bin/zegrep"];
    [array addObject:@"/bin/zfgrep"];
    [array addObject:@"/bin/zforce"];
    [array addObject:@"/bin/zgrep"];
    [array addObject:@"/bin/zless"];
    [array addObject:@"/bin/zmore"];
    [array addObject:@"/bin/znew"];
    [array addObject:@"/boot"];
    [array addObject:@"/lib"];
    [array addObject:@"/Library/dpkg"];
    [array addObject:@"/Library/LaunchDaemons"];
    [array addObject:@"/mnt"];
    [array addObject:@"/private/etc/alternatives"];
    [array addObject:@"/private/etc/apt"];
    [array addObject:@"/private/etc/default"];
    [array addObject:@"/private/etc/dpkg"];
    [array addObject:@"/private/etc/profile"];
    [array addObject:@"/private/etc/profile.d"];
    [array addObject:@"/private/etc/ssh"];
    [array addObject:@"/private/etc/ssl"];
    [array addObject:@"/private/var/backups"];
    [array addObject:@"/private/var/cache"];
    [array addObject:@"/private/var/empty"];
    [array addObject:@"/private/var/lib"];
    [array addObject:@"/private/var/local"];
    [array addObject:@"/private/var/lock"];
    [array addObject:@"/private/var/log/apt"];
    [array addObject:@"/private/var/spool"];
    [array addObject:@"/sbin/dmesg"];
    [array addObject:@"/sbin/dynamic_pager"];
    [array addObject:@"/sbin/halt"];
    [array addObject:@"/sbin/nologin"];
    [array addObject:@"/sbin/reboot"];
    [array addObject:@"/sbin/update_dyld_shared_cache"];
    [array addObject:@"/usr/bin/apt-key"];
    [array addObject:@"/usr/bin/arch"];
    [array addObject:@"/usr/bin/bashbug"];
    [array addObject:@"/usr/bin/c_rehash"];
    [array addObject:@"/usr/bin/captoinfo"];
    [array addObject:@"/usr/bin/cfversion"];
    [array addObject:@"/usr/bin/clear"];
    [array addObject:@"/usr/bin/cmp"];
    [array addObject:@"/usr/bin/db_archive"];
    [array addObject:@"/usr/bin/db_checkpoint"];
    [array addObject:@"/usr/bin/db_deadlock"];
    [array addObject:@"/usr/bin/db_dump"];
    [array addObject:@"/usr/bin/db_hotbackup"];
    [array addObject:@"/usr/bin/db_load"];
    [array addObject:@"/usr/bin/db_log_verify"];
    [array addObject:@"/usr/bin/db_printlog"];
    [array addObject:@"/usr/bin/db_recover"];
    [array addObject:@"/usr/bin/db_replicate"];
    [array addObject:@"/usr/bin/db_sql_codegen"];
    [array addObject:@"/usr/bin/db_stat"];
    [array addObject:@"/usr/bin/db_tuner"];
    [array addObject:@"/usr/bin/db_upgrade"];
    [array addObject:@"/usr/bin/db_verify"];
    [array addObject:@"/usr/bin/dbsql"];
    [array addObject:@"/usr/bin/df"];
    [array addObject:@"/usr/bin/diff"];
    [array addObject:@"/usr/bin/diff3"];
    [array addObject:@"/usr/bin/dirname"];
    [array addObject:@"/usr/bin/dpkg"];
    [array addObject:@"/usr/bin/dpkg-architecture"];
    [array addObject:@"/usr/bin/dpkg-buildflags"];
    [array addObject:@"/usr/bin/dpkg-buildpackage"];
    [array addObject:@"/usr/bin/dpkg-checkbuilddeps"];
    [array addObject:@"/usr/bin/dpkg-deb"];
    [array addObject:@"/usr/bin/dpkg-distaddfile"];
    [array addObject:@"/usr/bin/dpkg-divert"];
    [array addObject:@"/usr/bin/dpkg-genbuildinfo"];
    [array addObject:@"/usr/bin/dpkg-genchanges"];
    [array addObject:@"/usr/bin/dpkg-gencontrol"];
    [array addObject:@"/usr/bin/dpkg-gensymbols"];
    [array addObject:@"/usr/bin/dpkg-maintscript-helper"];
    [array addObject:@"/usr/bin/dpkg-mergechangelogs"];
    [array addObject:@"/usr/bin/dpkg-name"];
    [array addObject:@"/usr/bin/dpkg-parsechangelog"];
    [array addObject:@"/usr/bin/dpkg-query"];
    [array addObject:@"/usr/bin/dpkg-scanpackages"];
    [array addObject:@"/usr/bin/dpkg-scansources"];
    [array addObject:@"/usr/bin/dpkg-shlibdeps"];
    [array addObject:@"/usr/bin/dpkg-source"];
    [array addObject:@"/usr/bin/dpkg-split"];
    [array addObject:@"/usr/bin/dpkg-statoverride"];
    [array addObject:@"/usr/bin/dpkg-trigger"];
    [array addObject:@"/usr/bin/dpkg-vendor"];
    [array addObject:@"/usr/bin/find"];
    [array addObject:@"/usr/bin/getconf"];
    [array addObject:@"/usr/bin/getty"];
    [array addObject:@"/usr/bin/gpg"];
    [array addObject:@"/usr/bin/gpg-zip"];
    [array addObject:@"/usr/bin/gpgsplit"];
    [array addObject:@"/usr/bin/gpgv"];
    [array addObject:@"/usr/bin/gssc"];
    [array addObject:@"/usr/bin/hostinfo"];
    [array addObject:@"/usr/bin/infocmp"];
    [array addObject:@"/usr/bin/infotocap"];
    [array addObject:@"/usr/bin/iomfsetgamma"];
    [array addObject:@"/usr/bin/killall"];
    [array addObject:@"/usr/bin/ldrestart"];
    [array addObject:@"/usr/bin/locate"];
    [array addObject:@"/usr/bin/login"];
    [array addObject:@"/usr/bin/lzcat"];
    [array addObject:@"/usr/bin/lzcmp"];
    [array addObject:@"/usr/bin/lzdiff"];
    [array addObject:@"/usr/bin/lzegrep"];
    [array addObject:@"/usr/bin/lzfgrep"];
    [array addObject:@"/usr/bin/lzgrep"];
    [array addObject:@"/usr/bin/lzless"];
    [array addObject:@"/usr/bin/lzma"];
    [array addObject:@"/usr/bin/lzmadec"];
    [array addObject:@"/usr/bin/lzmainfo"];
    [array addObject:@"/usr/bin/lzmore"];
    [array addObject:@"/usr/bin/ncurses6-config"];
    [array addObject:@"/usr/bin/ncursesw6-config"];
    [array addObject:@"/usr/bin/openssl"];
    [array addObject:@"/usr/bin/pagesize"];
    [array addObject:@"/usr/bin/passwd"];
    [array addObject:@"/usr/bin/renice"];
    [array addObject:@"/usr/bin/reset"];
    [array addObject:@"/usr/bin/sbdidlaunch"];
    [array addObject:@"/usr/bin/sbreload"];
    [array addObject:@"/usr/bin/scp"];
    [array addObject:@"/usr/bin/script"];
    [array addObject:@"/usr/bin/sdiff"];
    [array addObject:@"/usr/bin/sftp"];
    [array addObject:@"/usr/bin/sort"];
    [array addObject:@"/usr/bin/ssh"];
    [array addObject:@"/usr/bin/ssh-add"];
    [array addObject:@"/usr/bin/ssh-agent"];
    [array addObject:@"/usr/bin/ssh-keygen"];
    [array addObject:@"/usr/bin/ssh-keyscan"];
    [array addObject:@"/usr/bin/sw_vers"];
    [array addObject:@"/usr/bin/tabs"];
    [array addObject:@"/usr/bin/tar"];
    [array addObject:@"/usr/bin/tic"];
    [array addObject:@"/usr/bin/time"];
    [array addObject:@"/usr/bin/toe"];
    [array addObject:@"/usr/bin/tput"];
    [array addObject:@"/usr/bin/tset"];
    [array addObject:@"/usr/bin/uicache"];
    [array addObject:@"/usr/bin/uiduid"];
    [array addObject:@"/usr/bin/uiopen"];
    [array addObject:@"/usr/bin/unlzma"];
    [array addObject:@"/usr/bin/unxz"];
    [array addObject:@"/usr/bin/update-alternatives"];
    [array addObject:@"/usr/bin/updatedb"];
    [array addObject:@"/usr/bin/which"];
    [array addObject:@"/usr/bin/xargs"];
    [array addObject:@"/usr/bin/xz"];
    [array addObject:@"/usr/bin/xzcat"];
    [array addObject:@"/usr/bin/xzcmp"];
    [array addObject:@"/usr/bin/xzdec"];
    [array addObject:@"/usr/bin/xzdiff"];
    [array addObject:@"/usr/bin/xzegrep"];
    [array addObject:@"/usr/bin/xzfgrep"];
    [array addObject:@"/usr/bin/xzgrep"];
    [array addObject:@"/usr/bin/xzless"];
    [array addObject:@"/usr/bin/xzmore"];
    [array addObject:@"/usr/games"];
    [array addObject:@"/usr/include/curses.h"];
    [array addObject:@"/usr/include/db_cxx.h"];
    [array addObject:@"/usr/include/db.h"];
    [array addObject:@"/usr/include/dbsql.h"];
    [array addObject:@"/usr/include/dpkg"];
    [array addObject:@"/usr/include/eti.h"];
    [array addObject:@"/usr/include/form.h"];
    [array addObject:@"/usr/include/lzma"];
    [array addObject:@"/usr/include/lzma.h"];
    [array addObject:@"/usr/include/menu.h"];
    [array addObject:@"/usr/include/nc_tparm.h"];
    [array addObject:@"/usr/include/ncurses_dll.h"];
    [array addObject:@"/usr/include/ncurses.h"];
    [array addObject:@"/usr/include/ncursesw"];
    [array addObject:@"/usr/include/openssl"];
    [array addObject:@"/usr/include/panel.h"];
    [array addObject:@"/usr/include/term_entry.h"];
    [array addObject:@"/usr/include/term.h"];
    [array addObject:@"/usr/include/termcap.h"];
    [array addObject:@"/usr/include/tic.h"];
    [array addObject:@"/usr/include/unctrl.h"];
    [array addObject:@"/usr/lib/apt"];
    [array addObject:@"/usr/lib/bash"];
    [array addObject:@"/usr/lib/engines"];
    [array addObject:@"/usr/lib/libapt-inst.2.0.0.dylib"];
    [array addObject:@"/usr/lib/libapt-inst.2.0.dylib"];
    [array addObject:@"/usr/lib/libapt-inst.dylib"];
    [array addObject:@"/usr/lib/libapt-pkg.5.0.1.dylib"];
    [array addObject:@"/usr/lib/libapt-pkg.5.0.dylib"];
    [array addObject:@"/usr/lib/libapt-pkg.dylib"];
    [array addObject:@"/usr/lib/libapt-private.0.0.0.dylib"];
    [array addObject:@"/usr/lib/libapt-private.0.0.dylib"];
    [array addObject:@"/usr/lib/libcrypto.1.0.0.dylib"];
    [array addObject:@"/usr/lib/libcrypto.a"];
    [array addObject:@"/usr/lib/libcrypto.dylib"];
    [array addObject:@"/usr/lib/libdb_sql-6.2.dylib"];
    [array addObject:@"/usr/lib/libdb_sql-6.dylib"];
    [array addObject:@"/usr/lib/libdb_sql.dylib"];
    [array addObject:@"/usr/lib/libdb-6.2.dylib"];
    [array addObject:@"/usr/lib/libdb-6.dylib"];
    [array addObject:@"/usr/lib/libdb.dylib"];
    [array addObject:@"/usr/lib/libdpkg.a"];
    [array addObject:@"/usr/lib/libdpkg.la"];
    [array addObject:@"/usr/lib/liblzma.a"];
    [array addObject:@"/usr/lib/liblzma.la"];
    [array addObject:@"/usr/lib/libssl.1.0.0.dylib"];
    [array addObject:@"/usr/lib/libssl.a"];
    [array addObject:@"/usr/lib/libssl.dylib"];
    [array addObject:@"/usr/lib/pkgconfig"];
    [array addObject:@"/usr/lib/ssl"];
    [array addObject:@"/usr/lib/terminfo"];
    [array addObject:@"/usr/libexec/apt"];
    [array addObject:@"/usr/libexec/bigram"];
    [array addObject:@"/usr/libexec/code"];
    [array addObject:@"/usr/libexec/cydia"];
    [array addObject:@"/usr/libexec/dpkg"];
    [array addObject:@"/usr/libexec/frcode"];
    [array addObject:@"/usr/libexec/gnupg"];
    [array addObject:@"/usr/libexec/rmt"];
    [array addObject:@"/usr/libexec/sftp-server"];
    [array addObject:@"/usr/libexec/ssh-keysign"];
    [array addObject:@"/usr/libexec/ssh-pkcs11-helper"];
    [array addObject:@"/usr/local/lib"];
    [array addObject:@"/usr/sbin/ac"];
    [array addObject:@"/usr/sbin/accton"];
    [array addObject:@"/usr/sbin/halt"];
    [array addObject:@"/usr/sbin/iostat"];
    [array addObject:@"/usr/sbin/mkfile"];
    [array addObject:@"/usr/sbin/pwd_mkdb"];
    [array addObject:@"/usr/sbin/reboot"];
    [array addObject:@"/usr/sbin/sshd"];
    [array addObject:@"/usr/sbin/startupfiletool"];
    [array addObject:@"/usr/sbin/sysctl"];
    [array addObject:@"/usr/sbin/vifs"];
    [array addObject:@"/usr/sbin/vipw"];
    [array addObject:@"/usr/sbin/zdump"];
    [array addObject:@"/usr/sbin/zic"];
    [array addObject:@"/usr/share/bigboss"];
    [array addObject:@"/usr/share/dict"];
    [array addObject:@"/usr/share/dpkg"];
    [array addObject:@"/usr/share/gnupg"];
    [array addObject:@"/usr/share/tabset"];
    [array addObject:@"/usr/share/terminfo"];
    // Potential Manual Files
    [array addObject:@"/bin/bash"];
    [array addObject:@"/authorize.sh"];
    [array addObject:@"/Applications/jjjj.app"];
    [array addObject:@"/Applications/Extender.app"];
    [array addObject:@"/Applications/GBA4iOS.app"];
    [array addObject:@"/Applications/Filza.app"];
    [array addObject:@"/Library/dpkg"];
    [array addObject:@"/Library/Cylinder"];
    [array addObject:@"/Library/LaunchDaemons"];
    [array addObject:@"/Library/Zeppelin"];
    [array addObject:@"/etc/alternatives"];
    [array addObject:@"/etc/apt"];
    [array addObject:@"/etc/dpkg"];
    [array addObject:@"/etc/dropbear"];
    [array addObject:@"/etc/pam.d"];
    [array addObject:@"/etc/profile.d"];
    [array addObject:@"/etc/ssh"];
    [array addObject:@"/usr/include"];
    [array addObject:@"/usr/lib/apt"];
    [array addObject:@"/usr/lib/dpkg"];
    [array addObject:@"/usr/lib/pam"];
    [array addObject:@"/usr/lib/pkgconfig"];
    [array addObject:@"/usr/lib/cycript0.9"];
    [array addObject:@"/usr/libexec/cydia"];
    [array addObject:@"/usr/libexec/gnupg"];
    [array addObject:@"/usr/share/bigboss"];
    [array addObject:@"/usr/share/dpkg"];
    [array addObject:@"/usr/share/gnupg"];
    [array addObject:@"/usr/share/tabset"];
    [array addObject:@"/private/var/cache/apt"];
    [array addObject:@"/private/var/db/stash"];
    [array addObject:@"/private/var/lib/apt"];
    [array addObject:@"/private/var/lib/dpkg"];
    [array addObject:@"/private/var/stash"];
    [array addObject:@"/private/var/tweak"];
    // Electra Beta Bootstrap
    [array addObject:@"/Applications/Anemone.app"];
    [array addObject:@"/Applications/SafeMode.app"];
    [array addObject:@"/usr/lib/SBInject.dylib"];
    [array addObject:@"/usr/lib/SBInject"];
    [array addObject:@"/usr/lib/libsubstitute.0.dylib"];
    [array addObject:@"/usr/lib/libsubstitute.dylib"];
    [array addObject:@"/usr/lib/libsubstrate.dylib"];
    [array addObject:@"/usr/lib/libjailbreak.dylib"];
    [array addObject:@"/usr/bin/recache"];
    [array addObject:@"/usr/bin/killall"];
    [array addObject:@"/usr/share/terminfo"];
    [array addObject:@"/usr/libexec/sftp-server"];
    [array addObject:@"/usr/lib/SBInject.dylib"];
    [array addObject:@"/Library/Frameworks"];
    [array addObject:@"/System/Library/Themes"];
    [array addObject:@"/bootstrap"];
    [array addObject:@"/Library/Themes"];
    [array addObject:@"/usr/lib/SBInject.dylib"];
    [array addObject:@"/Library/MobileSubstrate"];
    // Filza
    [array addObject:@"/Applications/Filza.app"];
    [array addObject:@"/private/var/root/Library/Filza"];
    [array addObject:@"/private/var/root/Library/Preferences/com.tigisoftware.Filza.plist"];
    [array addObject:@"/private/var/root/Library/Caches/com.tigisoftware.Filza"];
    [array addObject:@"/private/var/mobile/Library/Filza/"];
    [array addObject:@"/private/var/mobile/Library/Filza/.Trash"];
    [array addObject:@"/private/var/mobile/Library/Filza/.Trash.metadata"];
    [array addObject:@"/private/var/mobile/Library/Preferences/com.tigisoftware.Filza.plist"];
    // Liberios
    [array addObject:@"/etc/motd"];
    [array addObject:@"/.cydia_no_stash"];
    [array addObject:@"/Applications/Cydia.app"];
    [array addObject:@"/usr/share/terminfo"];
    [array addObject:@"/usr/local/bin"];
    [array addObject:@"/usr/local/lib"];
    [array addObject:@"/bin/zsh"];
    [array addObject:@"/etc/profile"];
    [array addObject:@"/etc/zshrc"];
    [array addObject:@"/usr/bin/scp"];
    [array addObject:@"/jb"];
    // ToPanga
    [array addObject:@"/etc/alternatives"];
    [array addObject:@"/etc/dpkg"];
    [array addObject:@"/etc/dropbear"];
    [array addObject:@"/etc/profile"];
    [array addObject:@"/etc/zshrc"];
    [array addObject:@"/usr/bin/apt"];
    [array addObject:@"/usr/bin/apt-get"];
    [array addObject:@"/usr/bin/cycc"];
    [array addObject:@"/usr/bin/cycript"];
    [array addObject:@"/usr/bin/cynject"];
    [array addObject:@"/usr/bin/dpkg"];
    [array addObject:@"/usr/bin/dpkg-deb"];
    [array addObject:@"/usr/bin/dpkg-divert"];
    [array addObject:@"/usr/bin/dpkg-maintscript-helper"];
    [array addObject:@"/usr/bin/dpkg-query"];
    [array addObject:@"/usr/bin/dpkg-split"];
    [array addObject:@"/usr/bin/dpkg-statoverride"];
    [array addObject:@"/usr/bin/dpkg-trigger"];
    [array addObject:@"/usr/bin/dselect"];
    [array addObject:@"/usr/bin/env"];
    [array addObject:@"/usr/bin/gnutar"];
    [array addObject:@"/usr/bin/gtar"];
    [array addObject:@"/usr/bin/uicache"];
    [array addObject:@"/usr/bin/update-alternatives"];
    [array addObject:@"/usr/include/dpkg"];
    [array addObject:@"/usr/include/substrate.h"];
    [array addObject:@"/usr/lib/apt"];
    [array addObject:@"/usr/lib/cycript0.9"];
    [array addObject:@"/usr/lib/dpkg"];
    [array addObject:@"/usr/lib/libapt-inst.dylib"];
    [array addObject:@"/usr/lib/libapt-pkg.dylib"];
    [array addObject:@"/usr/lib/libcrypto.1.0.0.dylib"];
    [array addObject:@"/usr/lib/libcurl.4.dylib"];
    [array addObject:@"/usr/lib/libcycript.0.dylib"];
    [array addObject:@"/usr/lib/libcycript.cy"];
    [array addObject:@"/usr/lib/libcycript.db"];
    [array addObject:@"/usr/lib/libcycript.dylib"];
    [array addObject:@"/usr/lib/libcycript.jar"];
    [array addObject:@"/usr/lib/libdpkg.a"];
    [array addObject:@"/usr/lib/libdpkg.la"];
    [array addObject:@"/usr/lib/libssl.1.0.0.dylib"];
    [array addObject:@"/usr/lib/libsubstrate.0.dylib"];
    [array addObject:@"/usr/lib/libsubstrate.dylib"];
    [array addObject:@"/usr/lib/pkgconfig"];
    [array addObject:@"/usr/share/dpkg"];
    [array addObject:@"/usr/local/bin"];
    [array addObject:@"/usr/local/lib"];
    [array addObject:@"/usr/libexec/cydia"];
    [array addObject:@"/usr/libexec/MSUnrestrictProcess"];
    [array addObject:@"/usr/libexec/substrate"];
    [array addObject:@"/usr/sbin/start-stop-daemon"];
    [array addObject:@"/private/var/lib"];
    [array addObject:@"/bin/bash"];
    [array addObject:@"/bin/bzip2"];
    [array addObject:@"/bin/bzip2_64"];
    [array addObject:@"/bin/cat"];
    [array addObject:@"/bin/chmod"];
    [array addObject:@"/bin/chown"];
    [array addObject:@"/bin/cp"];
    [array addObject:@"/bin/date"];
    [array addObject:@"/bin/dd"];
    [array addObject:@"/bin/hostname"];
    [array addObject:@"/bin/kill"];
    [array addObject:@"/bin/launchctl"];
    [array addObject:@"/bin/ln"];
    [array addObject:@"/bin/ls"];
    [array addObject:@"/bin/mkdir"];
    [array addObject:@"/bin/mv"];
    [array addObject:@"/bin/pwd"];
    [array addObject:@"/bin/rm"];
    [array addObject:@"/bin/rmdir"];
    [array addObject:@"/bin/sed"];
    [array addObject:@"/bin/sh"];
    [array addObject:@"/bin/sleep"];
    [array addObject:@"/bin/stty"];
    [array addObject:@"/bin/zsh"];
    [array addObject:@"/Applications/Cydia.app"];
    [array addObject:@"/Library/Frameworks"];
    [array addObject:@"/Library/MobileSubstrate"];
    [array addObject:@"/Library/test_inject_springboard.cy"];
    return array;
}

#ifdef WANT_CYDIA
void unjailbreak(int shouldEraseUserData)
#else    /* !WANT_CYDIA */
void unjailbreak(mach_port_t tfp0, uint64_t kernel_base, int shouldEraseUserData)
#endif    /* !WANT_CYDIA */
{
    // Initialize variables.
    int rv = 0;
#ifndef WANT_CYDIA
    uint64_t myOriginalCredAddr = 0;
#endif    /* WANT_CYDIA */
    NSMutableDictionary *md = nil;
    NSArray *cleanUpFileList = nil;
    
#ifndef WANT_CYDIA
    // Initialize QiLin.
    LOG("%@", NSLocalizedString(@"Initializing QiLin...", nil));
    rv = initQiLin(tfp0, kernel_base);
    LOG("rv: " "%d" "\n", rv);
    _assert(rv == 0);
    LOG("%@", NSLocalizedString(@"Successfully initialized QiLin.", nil));
#endif    /* WANT_CYDIA */
    
#ifndef WANT_CYDIA
    // Rootify myself.
    LOG("%@", NSLocalizedString(@"Rootifying myself...", nil));
    rv = rootifyMe();
    LOG("rv: " "%d" "\n", rv);
    _assert(rv == 0);
    LOG("%@", NSLocalizedString(@"Successfully rootified myself.", nil));
#endif    /* WANT_CYDIA */
    
#ifndef WANT_CYDIA
    // Escape Sandbox.
    LOG("%@", NSLocalizedString(@"Escaping Sandbox...", nil));
    myOriginalCredAddr = ShaiHuludMe(0);
    LOG("myOriginalCredAddr: " ADDR "\n", myOriginalCredAddr);
    LOG("%@", NSLocalizedString(@"Successfully escaped Sandbox.", nil));
#endif    /* WANT_CYDIA */
    
#ifndef WANT_CYDIA
    // Write a test file.
    
    LOG("%@", NSLocalizedString(@"Writing a test file...", nil));
    if (!access("/var/mobile/test.txt", F_OK)) {
        rv = unlink("/var/mobile/test.txt");
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
    }
    rv = fclose(fopen("/var/mobile/test.txt", "w+"));
    LOG("rv: " "%d" "\n", rv);
    _assert(rv == 0);
    rv = unlink("/var/mobile/test.txt");
    LOG("rv: " "%d" "\n", rv);
    _assert(rv == 0);
    LOG("%@", NSLocalizedString(@"Successfully wrote a test file.", nil));
#endif    /* WANT_CYDIA */
    
#ifndef WANT_CYDIA
    // Borrow entitlements from fsck_apfs.
    
    LOG("%@", NSLocalizedString(@"Borrowing entitlements from fsck_apfs...", nil));
    borrowEntitlementsFromDonor("/sbin/fsck_apfs", NULL);
    LOG("%@", NSLocalizedString(@"Successfully borrowed entitlements from fsck_apfs.", nil));
    
    // We now have fs_snapshot_rename.
#endif    /* WANT_CYDIA */
    
    // Revert to the system snapshot.
    LOG("%@", NSLocalizedString(@"Reverting to the system snapshot...", nil));
    rv = fs_snapshot_rename(open("/", O_RDONLY, 0), "orig-fs", systemSnapshot(copyBootHash()), 0);
    LOG("rv: " "%d" "\n", rv);
    _assert(rv == 0);
    LOG("%@", NSLocalizedString(@"Successfully put the system snapshot in place, it should revert on the next mount.", nil));
    
    md = [[NSMutableDictionary alloc] initWithContentsOfFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist"];
    _assert(md);
    md[@"SBShowNonDefaultSystemApps"] = @(NO);
    [md writeToFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist" atomically:YES];
    
    // Revert to the system snapshot.
    LOG("%@", NSLocalizedString(@"Reverting to the system snapshot...", nil));
    extern int SBDataReset(mach_port_t, int);
    extern mach_port_t SBSSpringBoardServerPort(void);
    mach_port_t SpringBoardServerPort = SBSSpringBoardServerPort();
    _assert(MACH_PORT_VALID(SpringBoardServerPort));
#ifdef WANT_CYDIA
    if (kCFCoreFoundationVersionNumber < 1452.23) {
        if (access("/var/MobileSoftwareUpdate/mnt1", F_OK)) {
            rv = mkdir("/var/MobileSoftwareUpdate/mnt1", 0755);
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
        }
        if (snapshot_check("/", "electra-prejailbreak") == 1) {
            rv = easyPosixSpawn([NSURL fileURLWithPath:@"/sbin/mount_apfs"], @[@"-s", @"electra-prejailbreak", @"/", @"/var/MobileSoftwareUpdate/mnt1"]);
        } else if (snapshot_check("/", "orig-fs") == 1) {
            rv = easyPosixSpawn([NSURL fileURLWithPath:@"/sbin/mount_apfs"], @[@"-s", @"orig-fs", @"/", @"/var/MobileSoftwareUpdate/mnt1"]);
        } else {
            rv = easyPosixSpawn([NSURL fileURLWithPath:@"/sbin/mount_apfs"], @[@"-s", [NSString stringWithFormat:@"%s", systemSnapshot(copyBootHash())], @"/", @"/var/MobileSoftwareUpdate/mnt1"]);
        }
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = waitForFile("/var/MobileSoftwareUpdate/mnt1/sbin/launchd");
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = easyPosixSpawn([NSURL fileURLWithPath:@"/usr/bin/rsync"], @[@"-vaxcH", @"--progress", @"--delete-after", @"/var/MobileSoftwareUpdate/mnt1/.", @"/"]);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
    }
    else {
#endif    /* !WANT_CYDIA */
#ifdef WANT_CYDIA
        rv = fs_snapshot_rename(open("/", O_RDONLY, 0), "orig-fs", systemSnapshot(copyBootHash()), 0);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
    }
#endif    /* !WANT_CYDIA */
    LOG("%@", NSLocalizedString(@"Successfully put the system snapshot in place, it should revert on the next mount.", nil));
    
    // Clean up.
    
    LOG("%@", NSLocalizedString(@"Cleaning up...", nil));
    cleanUpFileList = getCleanUpFileList();
    _assert(cleanUpFileList != nil);
    for (NSString *fileName in cleanUpFileList) {
        if (!access([fileName UTF8String], F_OK)) {
            _assert([[NSFileManager defaultManager] removeItemAtPath:fileName error:nil] == 1);
        }
    }
    LOG("%@", NSLocalizedString(@"Successfully cleaned up.", nil));
    
#ifndef WANT_CYDIA
    // Entitle myself.
    LOG("%@", NSLocalizedString(@"Entitling myself...", nil));
    rv = entitleMe("\t<key>platform-application</key>\n"
                   "\t<true/>\n"
                   "\t<key>com.apple.springboard.wipedevice</key>\n"
                   "\t<true/>");
    LOG("rv: " "%d" "\n", rv);
    _assert(rv == 0);
    LOG("%@", NSLocalizedString(@"Successfully entitled myself.", nil));
#endif    /* WANT_CYDIA */
    
    // Erase user data.
    LOG("%@", NSLocalizedString(@"Erasing user data...", nil));
    rv = SBDataReset(SpringBoardServerPort, shouldEraseUserData ? 5 : 1);
    LOG("rv: " "%d" "\n", rv);
    _assert(rv == 0);
    rv = reboot(0x400);
    LOG("rv: " "%d" "\n", rv);
    _assert(rv == 0);
    LOG("%@", NSLocalizedString(@"Successfully erased user data.", nil));
}

- (IBAction)tappedOnUnjailbreak:(id)sender {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0ul), ^{
        UIAlertController *alertController = [UIAlertController alertControllerWithTitle:NSLocalizedString(@"Confirmation", nil) message:NSLocalizedString(@"Are you sure want to erase all data and unjailbreak the device?", nil) preferredStyle:UIAlertControllerStyleAlert];
        UIAlertAction *OK = [UIAlertAction actionWithTitle:NSLocalizedString(@"Erase All", nil) style:UIAlertActionStyleDestructive handler:^(UIAlertAction * _Nonnull action) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [self.unjailbreakButton setEnabled:NO];
            });
            dispatch_async(dispatch_get_main_queue(), ^{
                [self.unjailbreakButton setAlpha:0.5];
            });
            dispatch_async(dispatch_get_main_queue(), ^{
                [self.resetUserDataSwitch setEnabled:NO];
            });
#ifndef WANT_CYDIA
            dispatch_async(dispatch_get_main_queue(), ^{
                [self.unjailbreakButton setTitle:NSLocalizedString(@"Exploiting...", nil) forState:UIControlStateDisabled];
            });
#endif    /* WANT_CYDIA */
#ifndef WANT_CYDIA
            // Initialize kernel exploit.
            LOG("%@", NSLocalizedString(@"Initializing kernel exploit...", nil));
            vfs_sploit();
#endif    /* WANT_CYDIA */
#ifndef WANT_CYDIA
            // Validate TFP0.
            LOG("%@", NSLocalizedString(@"Validating TFP0...", nil));
            _assert(MACH_PORT_VALID(tfp0));
            LOG("%@", NSLocalizedString(@"Successfully validated TFP0.", nil));
#endif    /* WANT_CYDIA */
            dispatch_async(dispatch_get_main_queue(), ^{
                [self.unjailbreakButton setTitle:NSLocalizedString(@"Unjailbreaking...", nil) forState:UIControlStateDisabled];
            });
            dispatch_async(dispatch_get_main_queue(), ^{
#ifdef WANT_CYDIA
                unjailbreak(self.resetUserDataSwitch.isOn);
#else    /* !WANT_CYDIA */
                unjailbreak(tfp0, (uint64_t)get_kernel_base(tfp0), self.resetUserDataSwitch.isOn);
#endif    /* !WANT_CYDIA */
            });
            dispatch_async(dispatch_get_main_queue(), ^{
                [self.unjailbreakButton setTitle:NSLocalizedString(@"Failed, reboot.", nil) forState:UIControlStateDisabled];
            });
        }];
        UIAlertAction *Cancel = [UIAlertAction actionWithTitle:NSLocalizedString(@"Cancel", nil) style:UIAlertActionStyleDefault handler:nil];
        [alertController addAction:OK];
        [alertController addAction:Cancel];
        [alertController setPreferredAction:Cancel];
        [self presentViewController:alertController animated:YES completion:nil];
    });
}
    
+ (NSURL *)getURLForUserName:(NSString *)userName {
    if ([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"tweetbot://"]]) {
        return [NSURL URLWithString:[NSString stringWithFormat:@"tweetbot:///user_profile/%@", userName]];
    } else if ([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"twitterrific://"]]) {
        return [NSURL URLWithString:[NSString stringWithFormat:@"twitterrific:///profile?screen_name=%@", userName]];
    } else if ([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"tweetings://"]]) {
        return [NSURL URLWithString:[NSString stringWithFormat:@"tweetings:///user?screen_name=%@", userName]];
    } else if ([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"twitter://"]]) {
        return [NSURL URLWithString:[NSString stringWithFormat:@"https://mobile.twitter.com/%@", userName]];
    } else {
        return [NSURL URLWithString:[NSString stringWithFormat:@"https://mobile.twitter.com/%@", userName]];
    }
}
    
- (IBAction)tappedOnMe:(id)sender {
    [[UIApplication sharedApplication] openURL:[ViewController getURLForUserName:@"Pwn20wnd"] options:@{} completionHandler:nil];
}
    
- (IBAction)tappedOnAesign_:(id)sender {
    [[UIApplication sharedApplication] openURL:[ViewController getURLForUserName:@"aesign_"] options:@{} completionHandler:nil];
}

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    NSMutableAttributedString *str = [[NSMutableAttributedString alloc] initWithString:@"Revert all changes,\nfor a stock iOS."];
    [str addAttribute:NSFontAttributeName value:[UIFont systemFontOfSize:19 weight:UIFontWeightBold] range:[@"Revert all changes,\nfor a stock iOS." rangeOfString:@"Revert "]];
    [str addAttribute:NSFontAttributeName value:[UIFont systemFontOfSize:19 weight:UIFontWeightMedium] range:[@"Revert all changes,\nfor a stock iOS." rangeOfString:@"all changes,\nfor a stock "]];
    [str addAttribute:NSFontAttributeName value:[UIFont systemFontOfSize:19 weight:UIFontWeightBold] range:[@"Revert all changes,\nfor a stock iOS." rangeOfString:@"iOS."]];
    [self.infoLabel setAttributedText:str];
    [self.unjailbreakButton addTarget:self action:@selector(tappedOnUnjailbreak:) forControlEvents:UIControlEventTouchUpInside];
    [self.myButton addTarget:self action:@selector(tappedOnMe:) forControlEvents:UIControlEventTouchUpInside];
    [self.aesign_Button addTarget:self action:@selector(tappedOnAesign_:) forControlEvents:UIControlEventTouchUpInside];
#ifndef WANT_CYDIA
    [self.QiLinLabel setHidden:NO];
#endif    /* WANT_CYDIA */
#ifdef WANT_CYDIA
    if (kCFCoreFoundationVersionNumber < 1443.00) {
#else    /* !WANT_CYDIA */
    if (kCFCoreFoundationVersionNumber <= 1451.51) {
#endif    /* !WANT_CYDIA */
        dispatch_async(dispatch_get_main_queue(), ^{
            [self.unjailbreakButton setEnabled:NO];
            [self.unjailbreakButton setTitle:NSLocalizedString(@"Incompatible version", nil) forState:UIControlStateDisabled];
            [self.unjailbreakButton setAlpha:0.5];
            [self.resetUserDataSwitch setEnabled:NO];
        });
    }
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (UIStatusBarStyle)preferredStatusBarStyle {
    return UIStatusBarStyleLightContent;
}

@end
