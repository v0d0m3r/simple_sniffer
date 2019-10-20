/*----------------------------------------------------------------------------*/

#include "Settings.h"
#include "Snif_lib.h"

/*----------------------------------------------------------------------------*/

#include <assert.h>
#include <getopt.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>
#include <ctype.h>

/*----------------------------------------------------------------------------*/

#include <pcap.h>

/*----------------------------------------------------------------------------*/

#include <json-c/json.h>

/*----------------------------------------------------------------------------*/

void cleanup_settings(Settings* sets)
{
    assert((sets != NULL) &&
           "cleanup_settings(): invalid arg");

    if (sets->filter) {
        free(sets->filter);
        sets->filter = NULL;
    }

    if (sets->is_clear_device && sets->device) {
        free(sets->device);
        sets->device = NULL;
    }
}

/*----------------------------------------------------------------------------*/

void print_usage()
{
    (void)fprintf(stderr, "Usage: simple_sniffer [-hp]\n");
    (void)fprintf(stderr, "\t\t\t[ -c config-file ] [ -i interface]\n");
    (void)fprintf(stderr, "\t\t\t[ expression ]\n");
}

/*----------------------------------------------------------------------------*/

static const char*const short_options = "c:hi:p";

static const char*const interface_option = "interface";
static const char*const no_promiscuous_mode = "no-promiscuous-mode";

/*----------------------------------------------------------------------------*/

static const struct option longopts[] = {
    { "config-file", required_argument, NULL, 'c' },
    { "help", no_argument, NULL, 'h' },
    { interface_option, required_argument, NULL, 'i' },
    { no_promiscuous_mode, no_argument, NULL, 'p' },
    { NULL, 0, NULL, 0 }
};

/*----------------------------------------------------------------------------*/

void set_value_str(char**const val, struct json_object* jobj, const char*const key)
{
    struct json_object* tmp;
    if (!json_object_object_get_ex(jobj, key, &tmp))
         merror("set_value_str(): can't get object by key: %s\n", key);

    const char* str = json_object_get_string(tmp);

    *val = (char*)malloc(strlen(str) * sizeof(char) + 1);
    if (!*val)
        merror("set_value_str(): malloc couldn't capture memory!\n");

    strncpy(*val, str, strlen(str)+1);
}

/*----------------------------------------------------------------------------*/

int get_value_int(struct json_object* jobj, const char* key)
{
    struct json_object* tmp;
    if (!json_object_object_get_ex(jobj, key, &tmp))
         merror("set_value_int(): can't get object by key: %s\n", key);

    const char* str = json_object_get_string(tmp);
    if (!isdigit((unsigned char)str[0]))
        merror("set_value_int(): can't get object by key: %s\n", key);

    intmax_t num = strtoimax(str, NULL, 10);
    if (num == INTMAX_MAX && errno == ERANGE)
        merror("set_value_int(): invalid convertion!\n");

    return (int)num;
}

/*----------------------------------------------------------------------------*/

void json_parsing(Settings* const sets, const char*const str)
{
    struct json_object* object = json_tokener_parse(str);
    if (!object)
        merror("json_parsing(): unable to parse contents of %s: %s\n",
               str, json_util_get_last_err());

    set_value_str(&sets->device, object, interface_option);
    set_value_str(&sets->filter, object, "filter");
    sets->pflag = get_value_int(object, no_promiscuous_mode);

    json_object_put(object);
}

/*----------------------------------------------------------------------------*/

void handle_config_file(Settings* const sets, const char*const fname)
{
    int fd = open(fname, O_RDONLY);
    if (fd == -1) {
        perror("Error opening file for reading");
        exit(EXIT_FAILURE);
    }

    struct stat statbuf;
    if (fstat(fd, &statbuf) < 0) {
        perror("Error opening file for reading");
        exit(EXIT_FAILURE);
    }

    char* map = mmap(0, (size_t)statbuf.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        close(fd);
        perror("Error mmapping the file");
        exit(EXIT_FAILURE);
    }

    json_parsing(sets, map);

    if (munmap(map, (size_t)statbuf.st_size) == -1) {
        perror("Error un-mmapping the file");
    }
    close(fd);
}

/*----------------------------------------------------------------------------*/

char* copy_argv(char **argv)
{
    char** p = argv;
    if (*p == NULL)
        return NULL;

    size_t len = 0;
    while (*p)
        len += strlen(*p++) + 1;

    char* buf = (char *)malloc(len);
    if (buf == NULL)
        merror("copy_argv(): malloc");

    p = argv;
    char* dst = buf;
    char* src;
    while ((src = *p++) != NULL) {
        while ((*dst++ = *src++) != '\0')
            ;
        dst[-1] = ' ';
    }
    dst[-1] = '\0';

    return buf;
}

/*----------------------------------------------------------------------------*/

void handle_options(int argc, char** argv, Settings* const sets)
{
    assert(sets!=NULL && "message");
    int op = 0;
    while (
        (op = getopt_long(argc, argv, short_options, longopts, NULL)) != -1)
        switch (op) {
        case 'c':
            handle_config_file(sets, optarg);            
            return;
        case 'h':
            print_usage();
            exit(S_SUCCESS);
        case 'i':
            sets->device = optarg;
            sets->is_clear_device = 0;
            break;
        case 'p':
            ++(sets->pflag);
            break;
        }

    sets->filter = copy_argv(&argv[optind]);
}

/*----------------------------------------------------------------------------*/

char* get_device_from_pcap(char* ebuf)
{
    pcap_if_t* devlist;

    /*
     * Find the list of interfaces, and pick
     * the first interface.
     */

    if (pcap_findalldevs(&devlist, ebuf) == -1)
        merror("%s", ebuf);
    if (devlist == NULL)
        merror("no interfaces available for capture");
    char* device = strdup(devlist->name);
    pcap_freealldevs(devlist);
    return device;
}

/*----------------------------------------------------------------------------*/

void load_settings(int argc, char** argv, Settings* const sets, char* ebuf)
{
    if (argc > 1)
        handle_options(argc, argv, sets);
    else
        handle_config_file(sets, "../settings.json");

    if (!sets->device)
        sets->device = get_device_from_pcap(ebuf);
}

/*----------------------------------------------------------------------------*/


