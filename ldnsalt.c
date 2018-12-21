#include <stdio.h>
#include <stdlib.h>

#define WIN_HOSTS_LOCATION "Windows/System32/drivers/etc/"
#define LN_UN_MC_LOCATION "etc/hosts"

/* Error codes */
#define UNSP_MT_WIN         31
#define INV_PERMS_LN_UN_MC  41
#define NMAP_HOSTSFILE      51
#define INV_FILE            52
#define INV_PERM            53
#define NO_BKP              54

void load_hostsfile(char *hostsfile_name, char *hosts_buf);
void build_hosts_buffer(struct hostsmap *maps, char *buf);
void logic_check(char *plat, struct options *opts);
void build_path(char *plat, char *path);
void loc_hosts_override(char *buf, char *path);
void restore_backup();
void display_help();

int main(int argc, char *argv[])
{
    
    char plat[MAX_PLATFORM_LENGTH];
    char hosts_buffer[MAX_HOSTSFILE_LENGTH];
    char path[MAX_PATH_LENGTH];
    
    syntax_check(argc, argv);
    parse(argc, argv);
    
    if (req_help)
        display_help();
    
    if (req_restore)
        restore_backup();
    
    map();
    
    logic_check(options_opts);
    
    platform(platform);
    
    if (has_hostsfile) {
        char hosts[MAX_HOSTSFILE_PATH_LENGTH];
        hostsfile(hosts);
        load_hostsfile(hosts, hosts_buffer);
    } else {
        resolve_map_loc();
        build_hosts_buffer(options_maps, hosts_buffer);
    }
    
    
    build_path(plat, path);
    loc_hosts_override(hosts_buffer, path, options_ldns_opts);
    
    return 0;
}

void load_hostsfile(char *hostsfile_name, char *hosts_buf)
{
    FILE *fl = fopen(hostsfile_name, "r");
    
    if (fl == NULL) {
        fprintf(stderr, "Error %d: Invalid file \"%s\".", INV_FILE, hostsfile_name);
        exit(1);
    }
    
    fscanf(fl, hosts_buf);
    
    fclose(fl);
        
}

void build_hosts_buffer(struct hostsmap *maps, char *buf)
{
    for (struct hostsmap *maps_cpy = maps; maps_cpy != NULL; maps_cpy++)
    {
        for (char **hosts = maps_cpy->src_hosts; hosts != NULL; hosts++) {
            strcat(buf, maps_cpy->dest_ip);
            strcat(buf, "\t");
            strcat(buf, hosts);
            strcat(buf, "\n");
        }
    }
}

void logic_check(char *plat, struct options *opts)
{
    if (strcmp(plat, "windows") == 0)
    {
        char dri_loc[MAX_DRIVE_LOC_LENGTH];
        drive_loc(dri_loc);
        if (dri_loc() == NULL) {
            fprintf(stderr, "Error %d: A mount location must be specified for a Windows DNS alteration.", UNSP_MT_WIN);
            exit(1);
        }
    }
    
    if (!has_hostsfile && !has_hostsmap) {
        fprintf(stderr, "Error %d: No hosts map or hostfile was specified.", NMAP_HOSTSFILE);
        exit(1);
    }
    
}

void build_path(char *plat, char *path)
{
    if (strcmp(plat, "windows") == 0)
    {
        char dri_loc[MAX_DRIVE_LOC_LENGTH];
        drive_loc(dri_loc);
        strcat(path, dri_loc);
        strcat(path, WIN_HOSTS_LOCATION);
    } else {
        char dri_loc[MAX_DRIVE_LOC_LENGTH];
        drive_loc(dri_loc);
        
        if (dri_loc != NULL)
            strcat(path, dri_loc);
        else
            strcat(path, "/");
        strcat(path, LN_UN_MC_LOCATION);
    }
}

void loc_hosts_override(char *buf, char *path, int opts)
{
    FILE *fl;
    
    char path_cpy[MAX_PATH_LENGTH];
    strcpy(path_cpy, path);
    
    if (opts & 0x01 == 0x01)
        fl = fopen(path, "w+");
    else
        fl = fopen(path, "w");
    
    if (opts & 0x02 == 0x02) {
        char tmp_buf[MAX_HOSTSFILE_LENGTH];
        fscanf(fl, tmp_buf);
        strcat(path_cpy, ".bkp");
        FILE *bkup = fopen(path_cpy, "w");
        
        if (bkup == NULL) {
            fprintf(stderr, "Error %d: Cannot backup hosts file \"%s\".", NO_BKP, path);
            exit(1);
        }
        
        fprintf(bkup, tmp_buf);
        fclose(bkup);
    }
    
    if (fl == NULL) {
        fprintf(stderr, "Error %d: Cannot open hosts file \"%s\".", INV_FILE, path);
        exit(1);
    }
    
    fprintf(fl, buf);
    
    fclose(fl);
}

void restore_backup(char *path)
{
    FILE *fl;
    char path_cpy[MAX_PATH_LENGTH];
    strcpy(path_cpy, path);
    strcat(path_cpy, ".bkp");
    fl = fopen(path_cpy, "r");
    
    if (fl == NULL) {
        fprintf(stderr, "Error %d: Cannot open backup file \"%s\".", NO_BKP, path_cpy);
        exit(1);
    }
    
    char buf[MAX_HOSTSFILE_LENGTH];
    fgets(fl, MAX_HOSTSFILE_LENGTH, buf);
    
}

void display_help()
{
    printf("Usage: ldnsalt [OPTIONS]\n\n");
    
    printf("Options:\n")
    printf("\t-a               Do not overwrite hosts file (append instead).\n");
    printf("\t-b               Make a backup copy of the current hosts file before altering it.\n");
    printf("\t-f [filename]    Specify a hosts file (conflicts with -m).\n");
    printf("\t-h               Display help menu.\n");
    printf("\t-m [dns map]     Specify a dns map instead of hosts file (conflicts with -f).\n");
    printf("\t\tExample dns map: google.com -> duckduckgo.com\n");
    printf("\t\tNow the google.com domain name is replaced with duckduckgo.com\'s IP address.\n");
    printf("\t\tAnother example: google.com,*.google.com,yahoo.com -> duckduckgo.com\n");
    printf("\t\tAll comma separated domain names will point to duckduck.com\n");
    printf("\t\tAnother example: youtube.com -> 192.168.1.1\n");
    printf("\t\tYoutube.com will point to 192.168.1.1\n");
    printf("\t-p [platform]    Used to specify a platform (if not specified, linux will be assumed).\n");
    printf("\t\tValid platforms include windows, macos, linux, and unix.");
    printf("\t-r               Restore a previously backed up hosts file.\n");
    exit(1);
}
