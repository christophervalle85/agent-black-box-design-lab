/*
 * v0.8 native Open Panel acceptance: a throwaway, synthetic fixture ONLY.
 *
 * This diagnostic NEVER reads the selected file or returns its path/contents.
 * No MCP or controller integration; no native worker transfer permission.
 * The sole permitted target is the harness-generated regular test file.
 */
#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

static int result(const char *marker,int status){
    puts(marker);
    fflush(stdout);
    return status;
}
static BOOL safeFixture(const char *path){
    if(!path || path[0]!='/' || strlen(path)>4096)return NO;
    struct stat details;
    if(lstat(path,&details)!=0 || !S_ISREG(details.st_mode) ||
       details.st_nlink!=1 || details.st_uid!=getuid() ||
       details.st_size!=28)
        return NO;
    return YES;
}
/*
 * NSOpenPanel may return /private/var/... where the test runner staged
 * /var/...; lexical paths differ even when both refer to the same file.
 *
 * Comparing lstat(2) device/inode identifies the exact fixture across
 * symlinked parent path aliases. Both leaves must remain independently
 * verified regular owner-owned files with nlink=1 and expected size, so a
 * user-selected symlink, hard link, or a different document is rejected.
 * This diagnostic NEVER opens or reads either selected file.
 */
static BOOL selectedIsExactFixture(const char *selected,const char *fixture){
    if(!safeFixture(selected) || !safeFixture(fixture))return NO;
    struct stat selectedStat,fixtureStat;
    if(lstat(selected,&selectedStat)!=0 || lstat(fixture,&fixtureStat)!=0)
        return NO;
    return selectedStat.st_dev==fixtureStat.st_dev &&
           selectedStat.st_ino==fixtureStat.st_ino;
}
int main(int argc,const char *argv[]){
    @autoreleasepool{
        const BOOL rejectOther=argc>=2 && strcmp(argv[1],"reject-other")==0;
        if((rejectOther ? argc!=4 : argc!=3) ||
           (strcmp(argv[1],"select")!=0 &&
            strcmp(argv[1],"cancel")!=0 && !rejectOther) ||
           !safeFixture(argv[2]))
            return result("BBX_MAC_PICKER_INVALID_FIXTURE",90);
        // A negative fixture is independently validated by the native
        // process. Success is never inferred from generic rejection.
        if(rejectOther &&
           (!safeFixture(argv[3]) ||
            selectedIsExactFixture(argv[2],argv[3])))
            return result("BBX_MAC_PICKER_INVALID_FIXTURE",90);
        NSString *fixture=[NSString stringWithUTF8String:argv[2]];
        if(![fixture.lastPathComponent isEqualToString:@"bbx-test-panel.txt"])
            return result("BBX_MAC_PICKER_INVALID_FIXTURE",90);
        if(rejectOther){
            NSString *alternate=[NSString stringWithUTF8String:argv[3]];
            if(![alternate.lastPathComponent isEqualToString:@"bbx-test-other.txt"] ||
               ![alternate.stringByDeletingLastPathComponent
                   isEqualToString:fixture.stringByDeletingLastPathComponent])
                return result("BBX_MAC_PICKER_INVALID_FIXTURE",90);
        }
        NSString *directory=fixture.stringByDeletingLastPathComponent;
        [NSApplication sharedApplication];
        [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
        NSOpenPanel *panel=[NSOpenPanel openPanel];
        panel.title=@"Agent Black Box — synthetic file-selection test";
        panel.message=rejectOther ?
            @"NEGATIVE TEST: select ONLY bbx-test-other.txt. This file MUST be rejected; do not select personal files." :
            @"Select ONLY bbx-test-panel.txt (or Cancel). No document will be read.";
        panel.prompt=@"Select Test File";
        panel.canChooseFiles=YES;
        panel.canChooseDirectories=NO;
        panel.allowsMultipleSelection=NO;
        panel.resolvesAliases=NO;
        panel.directoryURL=[NSURL fileURLWithPath:directory isDirectory:YES];
        [NSApp activateIgnoringOtherApps:YES];
        NSModalResponse chosen=[panel runModal];
        if(chosen==NSModalResponseCancel)
            return strcmp(argv[1],"cancel")==0?
                result("BBX_MAC_PICKER_USER_CANCELLED",83):
                result("BBX_MAC_PICKER_UNEXPECTED_CANCEL",85);
        if(chosen!=NSModalResponseOK)
            return result("BBX_MAC_PICKER_UNKNOWN_PANEL_RESULT",87);
        if(panel.URLs.count!=1 || !panel.URLs.firstObject.isFileURL)
            return result("BBX_MAC_PICKER_INVALID_SELECTION",87);
        NSString *selected=panel.URLs.firstObject.path;
        // The negative test only passes on the alternate synthetic fixture.
        // A generic rejection, cancellation, or selection of the allowed
        // fixture cannot count as evidence that wrong-file denial works.
        if(rejectOther){
            if([selected.lastPathComponent isEqualToString:@"bbx-test-other.txt"] &&
               selectedIsExactFixture(selected.fileSystemRepresentation,argv[3]))
                return result("BBX_MAC_PICKER_OTHER_FIXTURE_REJECTED",87);
            return result("BBX_MAC_PICKER_UNEXPECTED_SELECTION",86);
        }
        // No arbitrary file picker navigation can authorize a selection:
        // the sole valid OS result is the previously staged test fixture.
        // Match the generated file's stable identity, not a lexical
        // spelling that AppKit may normalize from /var to /private/var.
        if(![selected.lastPathComponent isEqualToString:@"bbx-test-panel.txt"] ||
           !selectedIsExactFixture(selected.fileSystemRepresentation,argv[2]))
            return result("BBX_MAC_PICKER_OUTSIDE_FIXTURE",87);
        if(strcmp(argv[1],"cancel")==0)
            return result("BBX_MAC_PICKER_UNEXPECTED_SELECTION",86);
        return result("BBX_MAC_PICKER_EXACT_FIXTURE_SELECTED",0);
    }
}
