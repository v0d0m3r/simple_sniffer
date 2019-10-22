/*----------------------------------------------------------------------------*/
/* Inner                                                                      */
#include "Settings.h"
#include "Snif_lib.h"

/*----------------------------------------------------------------------------*/

#include <assert.h>
#include <getopt.h>
#include <string.h>
#include <stdio.h>
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

void cleanup_settings(Settings*const sets)
{
    assert(sets != NULL && "cleanup_settings(): invalid arg!");

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

#define SHORT_OPTIONS "c:hi:p"
#define INTERFACE_OPTION "interface"
#define NO_PROMISCUOUS_MODE "no-promiscuous-mode"

/*----------------------------------------------------------------------------*/

static const struct option longopts[] = {
    { "config-file", required_argument, NULL, 'c' },
    { "help", no_argument, NULL, 'h' },
    { INTERFACE_OPTION, required_argument, NULL, 'i' },
    { NO_PROMISCUOUS_MODE, no_argument, NULL, 'p' },
    { NULL, 0, NULL, 0 }
};

/*----------------------------------------------------------------------------*/
/* Extract value by key from jobj and fill *val
 * set_value_str() uses malloc ==> you must look after val
 * Preconditions:  val != NULL && jobj != NULL && key != NULL
 * Postconditions: *val is 0-terminated string
 * Do exit from program if it'll get runtime error
*/
void set_value_str(char**const val, struct json_object*const jobj,
                   const char*const key)
{
    assert((val!=NULL && jobj!=NULL && key!=NULL)
           && "set_value_str(): invalid arg!");

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
/* Extract int-value by key from jobj
 * Preconditions:  jobj != NULL && key != NULL
 * Postconditions: none
 * Do exit from program if it'll get runtime error
*/
int get_value_int(struct json_object*const jobj, const char*const key)
{
    assert((jobj!=NULL && key!=NULL)
           && "set_value_int(): invalid arg!");

    struct json_object* tmp;
    if (!json_object_object_get_ex(jobj, key, &tmp))
         merror("set_value_int(): can't get object by key: %s\n", key);

    const char*const str = json_object_get_string(tmp);
    if (!isdigit((unsigned char)str[0]))    /* Simple checking: is it digit?  */
        merror("set_value_int(): can't get object by key: %s\n", key);

    intmax_t num = strtoimax(str, NULL, 10);
    if (num == INTMAX_MAX && errno == ERANGE)
        merror("set_value_int(): invalid convertion!\n");

    return (int)num;
}

/*----------------------------------------------------------------------------*/
/* Parse json document
 * Preconditions:  sets != NULL && str != NULL (str - 0-terminated string)
 * Postconditions: none
 * Do exit from program if it'll get runtime error
 *
 * Example json-config's format:
{
  "interface": "wlp3s0",
  "no-promiscuous-mode": 1,
  "filter": "ip6 and udp port 53"
}
*/
void json_parsing(Settings* const sets, const char*const str)
{
    assert((sets!=NULL && str!=NULL)
           && "json_parsing(): invalid arg!");
    struct json_object* object = json_tokener_parse(str);
    if (!object)
        merror("json_parsing(): unable to parse contents of %s\n", str);

    set_value_str(&sets->device, object, INTERFACE_OPTION);
    set_value_str(&sets->filter, object, "filter");
    sets->pflag = get_value_int(object, NO_PROMISCUOUS_MODE);

    json_object_put(object);
}

/*----------------------------------------------------------------------------*/
/* Try to open file and parsing it
 * Preconditions:  sets != NULL && fname != NULL
 * Postconditions: none
 * Do exit from program if it'll get runtime error
*/
void handle_config_file(Settings* const sets, const char*const fname)
{
    assert((sets!=NULL && fname!=NULL)
           && "handle_config_file(): invalid arg!");

    int fd = open(fname, O_RDONLY);
    if (fd == -1)
        merror("handle_config_file(): error opening file for reading: %s\n",
               fname);

    struct stat statbuf;
    if (fstat(fd, &statbuf) < 0)
        merror("handle_config_file(): error opening file for reading: %s\n",
               fname);

    char* map = mmap(0, (size_t)statbuf.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        close(fd);
        merror("handle_config_file(): error mmapping the file: %s\n",
               fname);
    }

    json_parsing(sets, map);

    if (munmap(map, (size_t)statbuf.st_size) == -1)
        merror("handle_config_file(): error un-mmapping the file: %s\n", fname);

    close(fd);
}

/*----------------------------------------------------------------------------*/
/* Copy info from argv to string allocated in dynamic memory
 * return NULL or pointer to string
 * Preconditions:  none
 * Postconditions: none
 * Do exit from program if it'll get runtime error
*/
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
        merror("copy_argv(): malloc can't get memory");

    p = argv;
    char* dst = buf;
    char* src;
    while ((src = *p++) != NULL) {
        while ((*dst++ = *src++) != '\0');
        dst[-1] = ' ';
    }
    dst[-1] = '\0';

    return buf;
}

/*----------------------------------------------------------------------------*/
/* Handle options from cmd
 * Preconditions: argv!=NULL && sets != NULL
 * Postconditions: none
 * Do exit from program if it'll get runtime error
*/
void handle_options(int argc, char** argv, Settings* const sets)
{
    assert((sets!=NULL && argv!=NULL)
           && "handle_options(): invalid args!");
    int op = 0;
    while (
        (op = getopt_long(argc, argv, SHORT_OPTIONS, longopts, NULL)) != -1)
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
/* Find the list of interfaces, and pick the first interface
 * Calling code should maintain resource
 * Preconditions:  ebuf != NULL
 * Postconditions: none
 * Do exit from program if it'll get runtime error
 */
char* get_device_from_pcap(char* ebuf)
{
    assert(ebuf != NULL && "get_device_from_pcap: invalid args!");

    pcap_if_t* devlist;
    if (pcap_findalldevs(&devlist, ebuf) == -1)
        merror("get_device_from_pcap(): %s", ebuf);
    if (devlist == NULL)
        merror("get_device_from_pcap(): no interfaces available for capture\n");
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
